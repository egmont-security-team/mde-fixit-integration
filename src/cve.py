"""
This module contains the Azure function that takes care of
the CVE related stuff. This means it is creating FixIt tickets
for devices hit by certain CVE.
"""

import os

import azure.functions as func
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

from lib.logging import logger
from lib.mde import MDEClient, MDEDevice, MDEVulnerability
from lib.fixit import FixItClient


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

    actions:
        - Create FixIt tickets for vulnerable devices.
        - Tags machine after creating FxiIt ticket.
    """

    # SETUP - start

    logger.info("Started the CVE Automation task.")

    credential = DefaultAzureCredential()

    try:
        key_vault_name = os.environ["KEY_VAULT_NAME"]
        if not key_vault_name:
            raise KeyError
    except KeyError:
        logger.critical(
            """
            Did not find environment variable \"KEY_VAULT_NAME\". Please set this 
            in \"local.settings.json\" or in the application settings in Azure.
            """
        )
        return

    secret_client = SecretClient(
        vault_url=f"https://{key_vault_name}.vault.azure.net",
        credential=credential,
    )

    # MDE secrets
    MDE_TENANT = secret_client.get_secret("Azure-MDE-Tenant").value
    MDE_CLIENT_ID = secret_client.get_secret("Azure-MDE-Client-ID").value
    MDE_SECRET_VALUE = secret_client.get_secret("Azure-MDE-Secret-Value").value

    # FixIt secrets
    FIXIT_4ME_BASE_URL = secret_client.get_secret("FixIt-4Me-Base-URL").value
    FIXIT_4ME_ACCOUNT = secret_client.get_secret("FixIt-4Me-Account").value
    FIXIT_4ME_API_KEY = secret_client.get_secret("FixIt-4Me-API-Key").value

    mde_client: MDEClient = MDEClient(MDE_TENANT, MDE_CLIENT_ID, MDE_SECRET_VALUE)
    fixit_client: FixItClient = FixItClient(
        FIXIT_4ME_BASE_URL, FIXIT_4ME_ACCOUNT, FIXIT_4ME_API_KEY
    )

    # SETUP - end

    devices: list[MDEDevice] = mde_client.get_devices()
    if not devices:
        logger.info("Task won't continue as there is no devices to process.")
        return

    vulnerabilities: list[MDEVulnerability] = mde_client.get_vulnerabilities()
    if not vulnerabilities:
        logger.info("Task won't continue as there is no vulnerabilities to process.")
        return

    multi_vulnerable_devices, single_vulnerable_devices = get_vulnerable_devices(vulnerabilities)

    multi_fixit_tickets: int = 0
    single_fixit_tickets: int = 0

    for device_uuid, vulnerability in single_vulnerable_devices.items():
        device = next((device for device in devices if device.uuid == device_uuid), None)

        if not device:
            logger.error(f"No device found with UUID={device_uuid}.")
            continue

        if device.should_skip("CVE", cve=vulnerability.cveId):
            continue

        if any(FixItClient.extract_id(tag) for tag in device.tags):
            logger.info(f"Skipping {device} because it has a FixIt request tag.")
            continue

        recommendations = mde_client.get_device_recommendations(device)
        if len(recommendations) < 1:
            logger.warning(f"{device} has no security recommendations.")
            continue

        logger.info(f"Creating single ticket for {device}.")
        fixit_id = fixit_client.create_single_device_fixit_requests(
            device, vulnerability, recommendations
        )

        if fixit_id:
            single_fixit_tickets += 1

            if not mde_client.alter_device_tag(device, f"#{fixit_id}", "Add"):
                logger.error(
                    f'Created FixIt ticket "#{fixit_id}" but failed to give {device} a tag.'
                )

    total_fixit_tickets = multi_fixit_tickets + single_fixit_tickets

    logger.info(
        f"Created a total of {total_fixit_tickets} FixIt-tickets (multi={multi_fixit_tickets}, single={single_fixit_tickets})"
    )


def get_vulnerable_devices(
    vulnerabilities: list[MDEVulnerability],
) -> (dict[str, list[str]], dict[str, MDEVulnerability]):
    """
    Returns a tuple containing all the vulnerable devices.

    The first element is multi vulnerabilities. This is vulnerabilities that have
    a lot of devices that are vulnerable, therefore they should be handled as a group.
    The value here is the UUID of the vulnerability and the value is the UUID list of
    vulnerable devices.

    The second element is single vulnerabilities. They all have few vulnerable devices,
    therefor they should be handled individually. The key here is the device UUID and the
    value is the vulnerability

    params:
        vulnerabilities:
            list[MDEVulnerability]: The list of vulnerabilities to process.

    returns:
        (dick[str, list[str]], dict[str, [MDEVulnerability]]): The dictionary containing
            the single and multi device vulnerabilities.
    """
    multi_vulnerable_devices: dict[str, list[str]] = {}
    single_vulnerable_devices: dict[str, MDEVulnerability] = {}

    for vulnerability in vulnerabilities:
        # TODO: Make device threshold setting in Azure portal. (20 is current threshold)
        if len(vulnerability.devices) > 20:
            multi_vulnerable_devices[vulnerability.uuid] = vulnerability.devices
            continue

        for device_uuid in vulnerability.devices:
            if not single_vulnerable_devices.get(device_uuid):
                single_vulnerable_devices[device_uuid] = vulnerability

    return (multi_vulnerable_devices, single_vulnerable_devices)
