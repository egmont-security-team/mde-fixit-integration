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
from azure.keyvault.secrets import SecretClient

from lib.fixit import FixItClient
from lib.mde import MDEClient, MDEDevice, MDEVulnerability
from lib.utils import get_secret

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
        logger.warning("The timer is past due!")

    # SETUP - start

    logger.info("Started the CVE Automation task.")

    try:
        key_vault_name = os.environ["KEY_VAULT_NAME"]
    except KeyError:
        logger.critical(
            """
            Did not find valid value for environment variable \"KEY_VAULT_NAME\".
            Please set this in \"local.settings.json\" or in the \"application settings\" in Azure.
            """
        )
        return

    secret_client = SecretClient(
        vault_url=f"https://{key_vault_name}.vault.azure.net",
        credential=DefaultAzureCredential(),
    )

    # MDE secrets
    MDE_TENANT = get_secret(secret_client, "Azure-MDE-Tenant")
    MDE_CLIENT_ID = get_secret(secret_client, "Azure-MDE-Client-ID")
    MDE_SECRET_VALUE = get_secret(secret_client, "Azure-MDE-Secret-Value")

    # FixIt secrets
    FIXIT_4ME_BASE_URL = get_secret(secret_client, "FixIt-4Me-Base-URL")
    FIXIT_4ME_ACCOUNT = get_secret(secret_client, "FixIt-4Me-Account")
    FIXIT_4ME_API_KEY = get_secret(secret_client, "FixIt-4Me-API-Key")

    FIXIT_SINGLE_TEMPLATE_ID = get_secret(secret_client, "CVE-Single-FixIt-Template-ID")
    FIXIT_MULTI_TEMPLATE_ID = get_secret(secret_client, "CVE-Multi-FixIt-Template-ID")
    FIXIT_SERVICE_INSTANCE_ID = get_secret(secret_client, "CVE-Service-Instance-ID")
    FIXIT_SD_TEAM_ID = get_secret(secret_client, "CVE-SD-Team-ID")
    FIXIT_EUX_TEAM_ID = get_secret(secret_client, "CVE-EUX-Team-ID")
    FIXIT_SEC_TEAM_ID = get_secret(secret_client, "CVE-SEC-Team-ID")

    mde_client = MDEClient(MDE_TENANT, MDE_CLIENT_ID, MDE_SECRET_VALUE)
    fixit_client = FixItClient(FIXIT_4ME_BASE_URL, FIXIT_4ME_ACCOUNT, FIXIT_4ME_API_KEY)

    # SETUP - end

    devices: list[MDEDevice] = mde_client.get_devices()
    if not devices:
        logger.critical("Task won't continue as there is no devices to process.")
        return

    vulnerabilities: list[MDEVulnerability] = mde_client.get_vulnerabilities()
    if not vulnerabilities:
        logger.critical(
            "Task won't continue as there is no vulnerabilities to process."
        )
        return

    multi_vulnerable_devices, single_vulnerable_devices = get_vulnerable_devices(
        vulnerabilities
    )

    multi_fixit_tickets: int = 0
    single_fixit_tickets: int = 0

    for device_uuid, vulnerability in single_vulnerable_devices.items():
        device = next((dev for dev in devices if dev.uuid == device_uuid), None)

        if not device:
            logger.warning(
                f'No device found with UUID="{device_uuid}" for single ticket. Skipping..'
            )
            continue

        if should_skip_device(device, vulnerability.cve_id):
            continue

        users = mde_client.get_device_users(device)
        recommendations = mde_client.get_device_recommendations(device)

        logger.info(f"Creating single ticket for {device}.")

        cve_page = f"https://security.microsoft.com/vulnerabilities/vulnerability/{vulnerability.cve_id}/overview"
        device_page = (
            f"https://security.microsoft.com/machines/v2/{device.uuid}/overview"
        )

        request_config: dict[str, Any] = {
            "service_instance_id": FIXIT_SERVICE_INSTANCE_ID,
            "template_id": FIXIT_SINGLE_TEMPLATE_ID,
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
            request_config["team"] = FIXIT_SEC_TEAM_ID
        else:
            request_config["team"] = FIXIT_SD_TEAM_ID

        fixit_res = fixit_client.create_request(
            f"Security[{vulnerability.cve_id}]: Single Vulnerable Device",
            **request_config,
        )

        if fixit_res is None:
            logger.error(
                f"Did not succesfully create the FixIt request for {device} (SINGLE). Skipping.."
            )
            continue

        single_fixit_tickets += 1

        fixit_id = fixit_res["id"]
        if not mde_client.alter_device_tag(device, f"#{fixit_id}", "Add"):
            logger.error(
                f'Created single FixIt ticket "#{fixit_id}" but failed to give {device} a tag.'
            )

    for cve_id, vulnerability in multi_vulnerable_devices.items():
        vulnerable_devices = []

        if not vulnerability.devices:
            logger.warning(
                f"Skipping {vulnerability} since it has no affected devices."
            )
            continue

        for device_uuid in vulnerability.devices:
            device = next((dev for dev in devices if dev.uuid == device_uuid), None)

            if not device:
                logger.error(
                    f'No device found with UUID="{device_uuid}" for multi ticket.'
                )
                continue

            if should_skip_device(device, cve_id):
                continue

            vulnerable_devices.append(device)

        if len(vulnerable_devices) < 1:
            break

        logger.info(f"Creating multi ticket for {device}.")

        cve_page = f"https://security.microsoft.com/vulnerabilities/vulnerability/{vulnerability.cve_id}/overview"

        device_count = str(len(vulnerable_devices))

        request_config: dict[str, Any] = {
            "service_instance_id": FIXIT_SERVICE_INSTANCE_ID,
            "team": FIXIT_EUX_TEAM_ID,
            "template_id": FIXIT_MULTI_TEMPLATE_ID,
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
            f"Security[{vulnerability.cve_id}]: Multiple Vulnerable Devices",
            **request_config,
        )

        if fixit_res is None:
            logger.error(
                f"Did not succesfully create the FixIt request for {vulnerability} (MULTI). Skipping.."
            )
            continue

        multi_fixit_tickets += 1

        fixit_id = fixit_res.get("id")
        for device in vulnerable_devices:
            if not mde_client.alter_device_tag(device, f"#{fixit_id}", "Add"):
                logger.error(
                    f'Created multi FixIt ticket "#{fixit_id}" but failed to give {device} devices a tag.'
                )

    total_fixit_tickets = multi_fixit_tickets + single_fixit_tickets

    logger.info(
        f"Created a total of {total_fixit_tickets} FixIt-tickets (multi={multi_fixit_tickets}, single={single_fixit_tickets})"
    )


def get_vulnerable_devices(
    vulnerabilities: list[MDEVulnerability],
) -> tuple[
    dict[str, MDEVulnerability],
    dict[str, MDEVulnerability],
]:
    """
    Returns a tuple containing all the vulnerable devices.

    The first element is a list of multi vulnerabilities. This is vulnerabilities that have
    a lot of devices that are vulnerable, therefore they should be handled as a group.
    The key is the UUID of the vulnerability and the value is the vulnerability itself.

    The second element is a list of single vulnerabilities. They all have few vulnerable devices,
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
        device_threshold = int(os.environ["CVE_DEVICE_THRESHOLD"])
    except KeyError as exception:
        logger.error("No device threshold specefied. Can't continue!")
        raise exception
    except ValueError as exception:
        logger.error("The device threshold is not a number. Can't continue!")
        raise exception

    for vulnerability in vulnerabilities:
        if vulnerability.devices is None:
            logger.warning(
                f"Skipping vulnerability {vulnerability} since it has no affected devices."
            )
            continue

        if len(vulnerability.devices) >= device_threshold:
            multi_vulnerable_devices[
                f"{vulnerability.cve_id}-{vulnerability.software_name}-{vulnerability.software_vendor}"
            ] = vulnerability
            continue

        for device_uuid in vulnerability.devices:
            # If there is multiple vulnerabilities for the same device, we only want to create one ticket still.
            if not single_vulnerable_devices.get(device_uuid):
                single_vulnerable_devices[device_uuid] = vulnerability

    return (multi_vulnerable_devices, single_vulnerable_devices)


def should_skip_device(device: MDEDevice, cve_id: str) -> bool:
    if not device.first_seen < (datetime.now(UTC) - timedelta(days=7)):
        logger.debug(
            f"Skipping {device} since it has not been in registered for more than 7 days."
        )
        return True

    if device.should_skip("CVE", cve=cve_id):
        logger.debug(
            f"Skipping {device} since its tags indicate it should be skipped for this automation."
        )
        return True

    if device.health == "Inactive":
        logger.debug(f'Skipping {device} since its health is "Inactive".')
        return True
    
    if device.onboarding_status != "Onboarded":
        logger.debug(f'Skipping {device} since its not onboarded yet.')
        return True

    if device.onboarding_status != "Onboarded":
        logger.debug(f"Skipping {device} since its not onboarded yet.")
        return True

    if any(FixItClient.extract_id(tag) for tag in device.tags):
        logger.debug(f"Skipping {device} because it has a FixIt request tag.")
        return True

    return False
