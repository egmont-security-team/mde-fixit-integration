"""
This module contains the Azure function that takes care of
the CVE related stuff. This means it is creating FixIt tickets
for devices hit by certain CVE.
"""

import logging
from datetime import UTC, datetime, timedelta
import os
from typing import Any

import azure.functions as func
from azure.identity import DefaultAzureCredential

from mde_fixit_integration.lib.fixit import FixItClient
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
    This function automatically creates a FixIt tickets for vulnerable devices.
    For detailed description of what this does refer to the README.md.

    Actions:
        - Create FixIt tickets for vulnerable devices.
        - Tags machine after creating FxiIt ticket.
    """
    if myTimer.past_due:
        logger.warning("The timer is past due for CVE!")
        return

    # SETUP - start

    logger.info("Started the CVE Automation task.")

    create_environment(DefaultAzureCredential())

    mde_client = MDEClient(
        os.environ["AZURE_MDE_TENANT"],
        os.environ["AZURE_MDE_CLIENT_ID"],
        os.environ["AZURE_MDE_SECRET_VALUE"],
    )
    fixit_client = FixItClient(
        os.environ["FIXIT_4ME_BASE_URL"],
        os.environ["FIXIT_4ME_ACCOUNT"],
        os.environ["FIXIT_4ME_API_KEY"],
    )

    # SETUP - end

    devices: list[MDEDevice] = mde_client.get_devices(
        odata_filter="(computerDnsName ne null) and (isExcluded eq false)"
    )
    if not devices:
        logger.critical("Task won't continue as there is no devices to process.")
        return

    vulnerabilities: list[MDEVulnerability] = mde_client.get_vulnerabilities()
    if not vulnerabilities:
        logger.critical("Task won't continue as there is no vulnerabilities to process.")
        return

    multi_vulnerable_devices, single_vulnerable_devices = get_vulnerable_devices(
        vulnerabilities
    )

    single_fixit_tickets_created = proccess_single_devices(
        single_vulnerable_devices, devices, mde_client, fixit_client
    )
    multi_fixit_tickets_created = proccess_multiple_devices(
        multi_vulnerable_devices, devices, mde_client, fixit_client
    )

    total_fixit_tickets_created = multi_fixit_tickets_created + single_fixit_tickets_created

    logger.info(f"Created a total of {total_fixit_tickets_created} Fix-It tickets (multi={multi_fixit_tickets_created}, single={single_fixit_tickets_created})")


def proccess_single_devices(
    single_vulnerable_devices: dict[str, MDEVulnerability],
    devices: list[MDEDevice],
    mde_client: MDEClient,
    fixit_client: FixItClient,
) -> int:
    """
    Processes the single vulnerable devices and creates FixIt tickets for them.

    params:
        single_vulnerable_devices:
            dict[str, MDEVulnerability]: The single vulnerable devices.
            The key is the device UUID and the value is the vulnerability.
    """
    single_fixit_tickets: int = 0

    for device_uuid, vulnerability in single_vulnerable_devices.items():
        device = next((dev for dev in devices if dev.uuid == device_uuid), None)

        if not device:
            logger.info(f'No device found with UUID="{device_uuid}" for single ticket. Skipping..')
            continue

        if should_skip_device(device, vulnerability.cve_id):
            continue

        logger.info(f"Creating single ticket for {device}.")

        users = mde_client.get_device_users(device)
        recommendations = mde_client.get_device_recommendations(device, odata_filter="remediationType eq 'Update'")

        cve_page = f"https://security.microsoft.com/vulnerabilities/vulnerability/{vulnerability.cve_id}/overview"
        device_page = f"https://security.microsoft.com/machines/v2/{device.uuid}/overview"

        request_config: dict[str, Any] = {
            "service_instance_id": os.environ["FIXIT_SERVICE_INSTANCE_ID"],
            "template_id": os.environ["FIXIT_SINGLE_TEMPLATE_ID"],
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
            request_config["team"] = os.environ["FIXIT_SEC_TEAM_ID"]
        elif device.is_server():
            request_config["team"] = os.environ["FIXIT_CAD_TEAM_ID"]
        else:
            request_config["team"] = os.environ["FIXIT_SD_TEAM_ID"]

        fixit_res = fixit_client.create_request(
            f"Security[{vulnerability.cve_id} - {vulnerability.cve_score}]: Single Vulnerable Device",
            **request_config,
        )

        if fixit_res is None:
            logger.error(f"Did not succesfully create the FixIt request for {device} (SINGLE). Skipping..")
            continue

        single_fixit_tickets += 1

        fixit_id = fixit_res["id"]
        if not mde_client.alter_device_tag(device, f"#{fixit_id}", "Add"):
            logger.error(f'Created single FixIt ticket "#{fixit_id}" but failed to give {device} a tag.')

    return single_fixit_tickets


def proccess_multiple_devices(
    multi_vulnerable_devices: dict[str, MDEVulnerability],
    devices: list[MDEDevice],
    mde_client: MDEClient,
    fixit_client: FixItClient,
) -> int:
    """
    Processes the multi vulnerable devices and creates FixIt tickets for them.

    params:
        multi_vulnerable_devices:
            dict[str, MDEVulnerability]: The multi vulnerable devices.
                The key is the vulnerability CVE ID and the value is the vulnerability.
            devices:
                list[MDEDevice]: The list of all devices.
            mde_client:
                MDEClient: The MDE client to interact with the MDE API.
            fixit_client:
                FixItClient: The FixIt client to interact with the FixIt API.

    returns:
        int: The amount of FixIt tickets created.
    """
    multi_fixit_tickets: int = 0

    open_multi_requests = fixit_client.list_requests(query_filter=f"status=assigned&template={os.environ['FIXIT_MULTI_TEMPLATE_ID']}")

    if open_multi_requests is None:
        logger.error("Failed to get open FixIt requests. Skipping multi ticket creation.")
        return 0

    for vulnerability in multi_vulnerable_devices.values():
        vulnerable_devices = []

        if any(get_cve_from_str(req["subject"]) == vulnerability.cve_id for req in open_multi_requests):
            logger.info(f"Skipping {vulnerability.cve_id} since there is already an open FixIt request for it.")
            continue

        for device_uuid in vulnerability.devices:
            device = next((dev for dev in devices if dev.uuid == device_uuid), None)

            if not device:
                logger.info(f'No device found with UUID="{device_uuid}" for multi ticket.')
                continue

            if should_skip_device(device, vulnerability.cve_id, check_fixit_request=False):
                continue

            vulnerable_devices.append(device)

        if len(vulnerable_devices) < 1:
            break

        logger.info(f"Creating multi ticket for {device}.")

        cve_page = f"https://security.microsoft.com/vulnerabilities/vulnerability/{vulnerability.cve_id}/overview"

        device_count = str(len(vulnerable_devices))

        request_config: dict[str, Any] = {
            "service_instance_id": os.environ["FIXIT_SERVICE_INSTANCE_ID"],
            "team": os.environ["FIXIT_MW_TEAM_ID"],
            "template_id": os.environ["FIXIT_MULTI_TEMPLATE_ID"],
            "custom_fields": [
                {"id": "cve_page", "value": cve_page},
                {"id": "cve_id", "value": vulnerability.cve_id},
                {"id": "cve_description", "value": vulnerability.description or ""},
                {"id": "software_name", "value": vulnerability.software_name or ""},
                {"id": "software_vendor", "value": vulnerability.software_vendor or ""},
                {"id": "device_count", "value": f"{device_count} affected devices"},
            ],
        }

        fixit_res = fixit_client.create_request(
            f"Security[{vulnerability.cve_id} - {vulnerability.cve_score}]: Multiple Vulnerable Devices",
            **request_config,
        )

        if fixit_res is None:
            logger.error(f"Did not succesfully create the FixIt request for {vulnerability} (MULTI). Skipping..")
            continue

        multi_fixit_tickets += 1

        fixit_id = fixit_res.get("id")
        for device in vulnerable_devices:
            if not mde_client.alter_device_tag(device, f"#{fixit_id}", "Add"):
                logger.error(f'Created multi FixIt ticket "#{fixit_id}" but failed to give {device} devices a tag.')

    return multi_fixit_tickets


def get_vulnerable_devices(
    vulnerabilities: list[MDEVulnerability],
) -> tuple[
    dict[str, MDEVulnerability],
    dict[str, MDEVulnerability],
]:
    """
    Returns a tuple containing all the vulnerable devices.

    The first element is a dict of multi vulnerabilities. This is vulnerabilities that have
    a lot of devices that are vulnerable, therefore they should be handled as a group.
    The key is the UUID of the vulnerability and the value is the vulnerability itself.

    The second element is a dict of single vulnerabilities. They all have few vulnerable devices,
    therefor they should be handled individually. The key is the device UUID and the value is
    the vulnerability

    params:
        vulnerabilities:
            list[MDEVulnerability]: The list of vulnerabilities to process.

    returns:
        tuple[dict[str, MDEVulnerability], dict[str, MDEVulnerabilityr]]:
            A tuple containing the multi and single device vulnerabilities.
    """
    multi_vulnerable_devices: dict[str, MDEVulnerability] = {}
    single_vulnerable_devices: dict[str, MDEVulnerability] = {}

    try:
        # Check README to understand the difference between these two thresholds.
        pc_threshold = int(os.environ["CVE_PC_THRESHOLD"])
        server_threshold = int(os.environ["CVE_SERVER_THRESHOLD"])
    except KeyError as exception:
        logger.error("No device threshold specefied. Can't continue!")
        raise exception
    except ValueError as exception:
        logger.error("The device threshold is not a number. Can't continue!")
        raise exception

    for vulnerability in vulnerabilities:
        if vulnerability.devices is None:
            logger.warning(f"Skipping vulnerability {vulnerability} since it has no affected devices.")
            continue

        threshold = server_threshold if vulnerability.is_sever_software() else pc_threshold
        if len(vulnerability.devices) >= threshold:
            device_key = f"{vulnerability.cve_id}-{vulnerability.software_name}-{vulnerability.software_vendor}"
            multi_vulnerable_devices[device_key] = vulnerability
            continue

        for device_uuid in vulnerability.devices:
            # If there is multiple vulnerabilities for the same device, we only want to create one ticket still.
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
    check_fixit_request: bool = True,
) -> bool:
    """
    Checks if a device should be skipped for the CVE automation.

    params:
        device:
            MDEDevice: The device to check.
        cve_id:
            str: The CVE ID to check against.
        check_first_seen:
            bool: If the device should be checked for first seen.
        check_should_skip:
            bool: If the device should be checked for tags that indicate it should be skipped.
        check_health:
            bool: If the device should be checked for health status.
        check_onboarding_status:
            bool: If the device should be checked for onboarding status.
        check_fixit_request:
            bool: If the device should be checked for FixIt requests tags.

    returns:
        bool: True if the device should be skipped.
    """
    if check_first_seen and not device.first_seen < (datetime.now(UTC) - timedelta(days=7)):
        logger.debug(f"Skipping {device} since it has not been in registered for more than 7 days.")
        return True

    if check_should_skip and device.should_skip("CVE", cve=cve_id):
        logger.debug(f"Skipping {device} since its tags indicate it should be skipped for this automation.")
        return True

    if check_health and device.health == "Inactive":
        logger.debug(f'Skipping {device} since its health is "{device.health}".')
        return True

    if check_onboarding_status and device.onboarding_status != "Onboarded":
        logger.debug(f"Skipping {device} since its not onboarded yet.")
        return True

    if check_fixit_request and any(FixItClient.extract_id(tag) for tag in device.tags):
        logger.debug(f"Skipping {device} because it has a FixIt request tag.")
        return True

    return False
