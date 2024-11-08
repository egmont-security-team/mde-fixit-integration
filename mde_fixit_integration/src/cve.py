"""
CVE Azure function.

This module features the Azure function that takes care of
the CVE related stuff. This means it is creating tickets
for devices hit by certain CVEs.
"""

import csv
import logging
import os
import tempfile
from datetime import UTC, datetime, timedelta
from typing import Any

import azure.functions as func
from azure.identity import DefaultAzureCredential

from mde_fixit_integration.lib.xurrent import XurrentClient
from mde_fixit_integration.lib.mde import MDEClient, MDEDevice, MDEVulnerability
from mde_fixit_integration.lib.utils import create_environment, get_cve_from_str

logger = logging.getLogger(__name__)

bp = func.Blueprint()


@bp.timer_trigger(
    schedule="0 0 8 * * 1-5",
    arg_name="myTimer",
    run_on_startup=False,
    use_monitor=True,
)
def cve_automation(myTimer: func.TimerRequest) -> None:
    """
    CVE automation.

    This function automatically creates a tickets for vulnerable devices.
    For detailed description of what this does refer to the README.md.

    Actions:
        - Create tickets for vulnerable devices.
        - Tags a machine after creating a ticket.
    """
    if myTimer.past_due:
        logger.warning("timer is past due for CVE!")
        return

    # SETUP - start

    logger.info("starting the CVE automation")

    create_environment(DefaultAzureCredential())

    mde_client = MDEClient(
        os.environ["AZURE_MDE_TENANT"],
        os.environ["AZURE_MDE_CLIENT_ID"],
        os.environ["AZURE_MDE_SECRET_VALUE"],
    )
    xurrent_client = XurrentClient(
        os.environ["XURRENT_BASE_URL"],
        os.environ["XURRENT_ACCOUNT"],
        os.environ["XURRENT_API_KEY"],
    )

    # SETUP - end

    devices: list[MDEDevice] = mde_client.get_devices(
        odata_filter="(computerDnsName ne null) and (isExcluded eq false)",
    )
    if not devices or len(devices) < 1:
        logger.critical("won't continue as there is no devices to process")
        return
    logger.info(f"fetched {len(devices)} devices to process")

    vulnerabilities: list[MDEVulnerability] = mde_client.get_vulnerabilities()
    if not vulnerabilities or len(vulnerabilities) < 1:
        logger.critical("won't continue as there is no vulnerabilities to process")
        return
    logger.info(f"fetched {len(vulnerabilities)} vulnerabilities to process")

    multi_vulnerable_devices, single_vulnerable_devices = get_vulnerable_devices(
        vulnerabilities,
    )

    single_tickets_created = proccess_single_devices(
        single_vulnerable_devices,
        devices,
        mde_client,
        xurrent_client,
    )
    multi_tickets_created = proccess_multiple_devices(
        multi_vulnerable_devices,
        devices,
        mde_client,
        xurrent_client,
    )

    total_tickets_created = multi_tickets_created + single_tickets_created

    logger.info(
        f"""created a total of {total_tickets_created} tickets; 
        (multi={multi_tickets_created}, single={single_tickets_created})""",
    )


def proccess_single_devices(
    single_vulnerable_devices: dict[str, MDEVulnerability],
    devices: list[MDEDevice],
    mde_client: MDEClient,
    xurrent_client: XurrentClient,
) -> int:
    """
    Process single vulnerable devices.

    Parameters
    ----------
    single_vulnerable_devices : dict[str, MDEVulnerability]
        The single vulnerable devices.
        The key is the device UUID and the value is the vulnerability.
    devices : list[MDEDevice]
        List of the devices to map against.
    mde_client : MDEClient
        Client to interact with MDE.
    xurrent_client : XurrentClient
        Client to interact with Xurrent.

    Returns
    -------
    int
        The amount of created tickets

    """
    single_tickets: int = 0

    for device_uuid, vulnerability in single_vulnerable_devices.items():
        device = next((dev for dev in devices if dev.uuid == device_uuid), None)

        if not device:
            logger.info(f'no device found with UUID="{device_uuid}" for single ticket')
            continue

        if should_skip_device(device, vulnerability.cve_id):
            continue

        logger.info(f"creating single ticket for {device}")

        users = mde_client.get_device_users(device)
        recommendations = mde_client.get_device_recommendations(
            device,
            odata_filter="remediationType eq 'Update'",
        )  # Use filter to only get software update recommendation

        cve_page = f"https://security.microsoft.com/vulnerabilities/vulnerability/{vulnerability.cve_id}/overview"
        device_page = (
            f"https://security.microsoft.com/machines/v2/{device.uuid}/overview"
        )

        request_config: dict[str, Any] = {
            "service_instance_id": os.environ["CVE_SERVICE_INSTANCE_ID"],
            "template_id": os.environ["CVE_SINGLE_TEMPLATE_ID"],
            "custom_fields": [
                {"id": "cve_page", "value": cve_page},
                {"id": "cve_id", "value": vulnerability.cve_id},
                {"id": "cve_description", "value": vulnerability.description},
                {"id": "software_name", "value": vulnerability.software_name},
                {"id": "software_vendor", "value": vulnerability.software_vendor},
                {"id": "device_page", "value": device_page},
                {"id": "device_name", "value": device.name},
                {"id": "device_uuid", "value": device.uuid},
                {"id": "device_os", "value": device.os},
                {"id": "device_users", "value": ", ".join(users or ["Unknown"])},
                {"id": "recommendations", "value": "\n".join(recommendations)},
            ],
        }

        if len(recommendations) == 0:
            request_config["team"] = os.environ["CVE_SOC_TEAM_ID"]
        elif device.is_server():
            request_config["team"] = os.environ["CVE_CAD_TEAM_ID"]
        else:
            request_config["team"] = os.environ["CVE_SD_TEAM_ID"]

        ticket_id = f"{vulnerability.cve_id} - {vulnerability.cve_score}"
        ticket_res = xurrent_client.create_ticket(
            f"Security[{ticket_id}]: Single Vulnerable Device",
            **request_config,
        )

        if ticket_res is None:
            logger.error(
                "did not succesfully create the ticket",
                extra={
                    "device": str(device),
                },
            )
            continue

        single_tickets += 1

        ticket_id = ticket_res["id"]
        if not mde_client.alter_device_tag(device, f"#{ticket_id}", "Add"):
            logger.error(
                f'failed to give {device} tag "#{ticket_id}"',
                extra={
                    "device": str(device),
                    "ticket_id": ticket_id,
                },
            )

    return single_tickets


def proccess_multiple_devices(
    multi_vulnerable_devices: dict[str, MDEVulnerability],
    devices: list[MDEDevice],
    mde_client: MDEClient,
    xurrent_client: XurrentClient,
) -> int:
    """
    Process multi vulnerable devices.

    Parameters
    ----------
    multi_vulnerable_devices : dict[str, MDEVulnerability]
        Multi vulnerable devices.
        Key is the CVE ID and the value is the vulnerability.
    devices : list[MDEDevice]
        List of all devices.
    mde_client : MDEClient
        Client to interact with the MDE API.
    xurrent_client : XurrentClient
       Client to interact with the Xurrent API.

    Returns
    -------
    int
        The amount of created multi tickets

    """
    multi_tickets: int = 0

    multi_template_id = os.environ["CVE_MULTI_TEMPLATE_ID"]
    open_multi_requests = xurrent_client.list_tickets(
        query_filter=f"status=assigned&template={multi_template_id}",
    )

    for key, vulnerability in multi_vulnerable_devices.items():
        vulnerable_devices = []

        if any(has_open_ticket(req, vulnerability) for req in open_multi_requests):
            logger.info(
                f"{vulnerability.cve_id} already has a open multi ticket",
                extra={
                    "vulnerability": str(vulnerability),
                },
            )
            continue

        for device_uuid in vulnerability.devices:
            device = next((dev for dev in devices if dev.uuid == device_uuid), None)

            if not device:
                logger.info(
                    f'no device found with UUID "{device_uuid}" for multi ticket',
                    extra={
                        "deivce_uuid": device_uuid,
                    },
                )
                continue

            if should_skip_device(
                device,
                vulnerability.cve_id,
                check_ticket=False,
            ):
                continue

            vulnerable_devices.append(device)

        if len(vulnerable_devices) < 1:
            break

        logger.info(f"creating multi ticket for {device}")

        attachment_key = xurrent_client.upload_file(
            create_csv_file(key, vulnerable_devices),
        )

        cve_page = f"https://security.microsoft.com/vulnerabilities/vulnerability/{vulnerability.cve_id}/overview"
        device_count = str(len(vulnerable_devices))

        request_config: dict[str, Any] = {
            "service_instance_id": os.environ["CVE_SERVICE_INSTANCE_ID"],
            "template_id": os.environ["CVE_MULTI_TEMPLATE_ID"],
            "custom_fields": [
                {"id": "cve_page", "value": cve_page},
                {"id": "cve_id", "value": vulnerability.cve_id},
                {"id": "cve_description", "value": vulnerability.description},
                {"id": "software_name", "value": vulnerability.software_name},
                {"id": "software_vendor", "value": vulnerability.software_vendor},
                {"id": "devices_count", "value": f"{device_count} affected devices"},
            ],
            "internal_note": f"""
                Attached is a list of {device_count}
                devices affected by this vulnerability.
            """,
            "internal_note_attachments": [
                {
                    "key": attachment_key,
                }
            ],
        }

        if vulnerability.is_server_software():
            request_config["team"] = os.environ["CVE_CAD_TEAM_ID"]
        else:
            request_config["team"] = os.environ["CVE_MW_TEAM_ID"]

        ticket_id = f"{vulnerability.cve_id} - {vulnerability.cve_score}"
        ticket_res = xurrent_client.create_ticket(
            f"Security[{ticket_id}]: Multiple Vulnerable Devices", 
            **request_config,
        )

        if ticket_res is None:
            logger.error(
                f"failed to create the ticket for {vulnerability} (MULTI)",
                extra={
                    "device": str(device),
                },
            )
            continue

        multi_tickets += 1

        ticket_id = ticket_res["id"]
        for device in vulnerable_devices:
            if not mde_client.alter_device_tag(device, f"#{ticket_id}", "Add"):
                logger.error(
                    f'failed to give {device} tag "#{ticket_id}"',
                    extra={
                        "device": str(device),
                        "ticket_id": ticket_id,
                    },
                )

    return multi_tickets


def get_vulnerable_devices(
    vulnerabilities: list[MDEVulnerability],
) -> tuple[
    dict[str, MDEVulnerability],
    dict[str, MDEVulnerability],
]:
    """
    Get a tuple containing all the vulnerable devices.

    The first element is a dict of multi vulnerabilities. This is vulnerabilities that
    have a lot of devices that are vulnerable, therefore they should be handled as a
    group. The key is the UUID of the vulnerability and the value is the vulnerability
    itself.

    The second element is a dict of single vulnerabilities. They all have few vulnerable
    devices, therefor they should be handled individually. The key is the device UUID
    and the value is the vulnerability.

    Parameters
    ----------
    vulnerabilities : list[MDEVulnerability]
        The list of vulnerabilities to process.

    Returns
    -------
    tuple[
        dict[str, MDEVulnerability],
        dict[str, MDEVulnerabilityr]
    ]
        A tuple containing the multi and single vulnerable devices.

    """
    multi_vulnerable_devices: dict[str, MDEVulnerability] = {}
    single_vulnerable_devices: dict[str, MDEVulnerability] = {}

    try:
        # Check README to understand the difference between these two thresholds.
        threshold = int(os.environ["CVE_THRESHOLD"])
        threshold_server = int(os.environ["CVE_SERVER_THRESHOLD"])
    except KeyError as exception:
        logger.error("device threshold not specefied; can't continue!")
        raise exception
    except ValueError as exception:
        logger.error("device threshold is not a number; can't continue!")
        raise exception

    for vulnerability in vulnerabilities:
        if vulnerability.devices is None:
            logger.warning(f"no affected devices; skipping {vulnerability}")
            continue

        if vulnerability.is_server_software():
            threshold = threshold_server

        if len(vulnerability.devices) >= threshold:
            vulnerability_key = f"""
                {vulnerability.cve_id}-{vulnerability.software_name}-{vulnerability.software_vendor}
            """

            if multi_vulnerable_devices.get(vulnerability_key):
                logger.error("multi device vulnerability alread exists; skipping!")
                continue

            multi_vulnerable_devices[vulnerability_key] = vulnerability
            continue

        for device_uuid in vulnerability.devices:
            # If there is multiple vulnerabilities for the same
            # device we only want to create one ticket still.
            if not single_vulnerable_devices.get(device_uuid):
                single_vulnerable_devices[device_uuid] = vulnerability

    return (multi_vulnerable_devices, single_vulnerable_devices)


def should_skip_device(
    device: MDEDevice,
    cve_id: str,
    check_first_seen: bool = True,
    check_should_skip: bool = True,
    check_health: bool = True,
    check_onboarding_status: bool = True,
    check_ticket: bool = True,
) -> bool:
    """
    Check if a device should be skipped for the CVE automation.

    Parameters
    ----------
    device : MDEDevice
        The device to check.
    cve_id : str
        The CVE ID to check against.
    check_first_seen : bool
        If the device should be checked for first seen.
    check_should_skip : bool
        If the device should be checked for tags that indicate it should be skipped.
    check_health : bool
        If the device should be checked for health status.
    check_onboarding_status : bool
        If the device should be checked for onboarding status.
    check_ticket : bool
        If the device should be checked for ticket tags.

    Returns
    -------
    bool
        True if the device should be skipped.

    """
    # Skip if device is not older than 1 week
    one_week_back = datetime.now(UTC) - timedelta(days=7)
    if check_first_seen and not device.first_seen < one_week_back:
        logger.debug(f"skipping {device}; not registered for more than 7 days")
        return True

    # Skip if device is marked for skipping
    if check_should_skip and device.should_skip("CVE", cve=cve_id):
        logger.debug(f"skipping {device}; marked for skipping")
        return True

    # Skip if device is inactive 
    if check_health and device.health == "Inactive":
        logger.debug(f"skipping {device}; health is {device.health}")
        return True

    # Skip if device is not onboarded yet
    if check_onboarding_status and device.onboarding_status != "Onboarded":
        logger.debug(f"skipping {device}; not onboarded yet")
        return True

    # Skip if device has any ticket tags (does not check ticket status)
    if check_ticket and any(XurrentClient.extract_id(tag) for tag in device.tags):
        logger.debug(f"skipping {device}; has a ticket tag")
        return True

    return False


def create_csv_file(file_name: str, devices: list[MDEDevice]) -> str:
    """
    Create a CSV file with devices.

    This will add the ".csv" mimetype to the file and return the path.
    The file will be stored in the "temp" directory on the local machine.

    Parameters
    ----------
    file_name : str
        The name of the file to create.
    devices : list[MDEDevice]
        The devices to write to the file.

    Returns
    -------
    str
        The key of the file in attachment storage.

    """
    target_dir = os.path.join(tempfile.gettempdir(), "mde_fixit_integration")
    os.makedirs(target_dir, exist_ok=True)

    if not file_name.endswith(".csv"):
        file_name += ".csv"

    file_path = os.path.join(target_dir, file_name)

    with open(file_path, "w+", encoding="utf8") as file:
        writer = csv.writer(file)

        keys_to_save = [
            "uuid",
            "name",
            "health",
            "os",
            "onboarding_status",
            "first_seen",
        ]

        writer.writerow(keys_to_save)

        for device in devices:
            writer.writerow([getattr(device, key) for key in keys_to_save])

    return file_path


def has_open_ticket(vulnerability: MDEVulnerability, open_multi_tickets: Any) -> bool:
    """
    Wether a ticket already has an open ticket.

    Parameters
    ----------
    vulnerability : MDEVulnerability
        The vulnerability
    open_multi_tickets : Any
        All open multi tickets

    Returns
    -------
    bool
        Wether the ticket already exists

    """
    return any(
        get_cve_from_str(req["subject"]) == vulnerability.cve_id
        for req in open_multi_tickets
    )
