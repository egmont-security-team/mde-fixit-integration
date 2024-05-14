"""
This module contains the Azure function that takes care of the
Data Defender cleanup tasks. This means it cleans up duplicate
devices and removes FixIt tags that has the relative request completed.
"""

import os

import azure.functions as func
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

from lib.logging import logger
from lib.mde import MDEClient
from lib.fixit import FixItClient


bp = func.Blueprint()


@bp.timer_trigger(
    schedule="0 0 6 * * 1-5",
    arg_name="myTimer",
    run_on_startup=False,
    use_monitor=False,
)
def ddc2_automation(myTimer: func.TimerRequest) -> None:
    """
    This is the main Azure Function that takes care of the Data Defender Cleanup task 2.
    For detailed description of what this does refer to the README.md.

    Actions:
        - Removes closed FixIt tags from devices.
    """

    logger.info("Started the Data Defender Cleanup task 2.")

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
    FIXIT_4ME_ACCOUNT = secret_client.get_secret("FixIt-4Me-Account").value
    FIXIT_4ME_BASE_URL = secret_client.get_secret("FixIt-4Me-Base-URL").value
    FIXIT_4ME_API_KEY = secret_client.get_secret("FixIt-4Me-API-Key").value

    mde_client: MDEClient = MDEClient(MDE_TENANT, MDE_CLIENT_ID, MDE_SECRET_VALUE)
    fixit_client: FixItClient = FixItClient(
        FIXIT_4ME_BASE_URL, FIXIT_4ME_ACCOUNT, FIXIT_4ME_API_KEY
    )

    devices = mde_client.get_devices()

    if not devices:
        logger.info("Task won't continue as there is no devices to process.")
        return

    logger.info(
        "Start removing FixIt tags that reference a completed request from devices in the Microsoft Defender portal."
    )

    removed_fixit_tags = 0

    for device in devices:
        if device.should_skip(automation_names=["DDC2"]):
            continue

        for tag in device.tags:
            request_id = FixItClient.extract_id(tag)

            if not request_id:
                continue

            request_status = fixit_client.get_fixit_request_status(request_id)

            if request_status == "completed":
                if mde_client.alter_device_tag(device, tag, "Remove"):
                    removed_fixit_tags += 1

    logger.info(
        "Finished removing {} Fix-It tags from devices in the Microsoft Defender portal.".format(
            removed_fixit_tags
        )
    )
