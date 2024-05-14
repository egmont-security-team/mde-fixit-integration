"""
This module contains the Azure function that takes care of
the CVE related stuff. This means creating FixIt tickets for devices
hit by certain CVE's.
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
    run_on_startup=True,
    use_monitor=False,
)
def cve_automation(myTimer: func.TimerRequest) -> None:
    """
    TODO: This function is WIP.
    """

    logger.info("Started the CVE Automation tasks.")

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
        vault_url="https://{}.vault.azure.net".format(key_vault_name),
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

    vulnerabilities: list[MDEVulnerability] = mde_client.get_vulnerabilities()

    if not vulnerabilities:
        logger.info("Task won't continue as there is no vulnerabilities to process.")
        return

    multi_fixit_tickets: int = 0
    single_fixit_tickets: int = 0

    vulnerable_devices: dict[MDEDevice] = {}

    for vulnerability in vulnerabilities:
        # TODO: Make device threshold setting in Azure portal. (20 is current threshold)
        if len(vulnerability.devices) > 20:
            logger.info("Creating multi FixIt-ticket for {}.".format(vulnerability))
            multi_fixit_tickets += 1
            continue

        for device in vulnerability.devices:
            if not device.should_skip(
                automations=["CVE-SPECIFIC"],
                cve=vulnerability.cveId
            ) and not vulnerable_devices.get(device.uuid):
                vulnerable_devices[device.uuid] = {
                    "device": device,
                    "vulnerability": vulnerability,
                }

    for uuid, info in vulnerable_devices.items():
        device = info.get("device")
        vulnerability = info.get("vulnerability")

        if not device.should_skip(
            automations=["CVE-SPECIFIC"],
            cve=vulnerability.cveId
        ) and not vulnerable_devices.get(device.uuid):
            continue

        if any(FixItClient.extract_id(tag) for tag in device.tags):
            logger.info(
                "Skipping {} because it has a fixit request tag.".format(device)
            )
            continue

        recommendations = mde_client.get_device_recommendations(device)
        if len(recommendations) < 1:
            logger.warning(
                "Skipping {} because is has no security recommendations.".format(device)
            )
            continue

        logger.info("Creating single ticket for {}.".format(device))
        fixit_id = fixit_client.create_single_device_fixit_requests(
            device, vulnerability, recommendations
        )

        if fixit_id:
            if not mde_client.alter_device_tag(device, "#{}".format(fixit_id), "Add"):
                logger.error(
                    'Created FixIt ticket "#{}" but failed to give {} a tag.'.format(
                        fixit_id, device
                    )
                )
            single_fixit_tickets += 1

    total_fixit_tickets = multi_fixit_tickets + single_fixit_tickets
    logger.info(
        "Created a total of {} FixIt-tickets (multi={}, single={}, looked_at_devices={})".format(
            total_fixit_tickets, multi_fixit_tickets, single_fixit_tickets, len(list(vulnerable_devices.keys()))
        )
    )
