"""
This module contains the Azure function that takes care of the
Data Defender cleanup task 2. This means it removes FixIt tags
from devices where the relative request is completed.
"""

import logging
import os

import azure.functions as func
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

from lib.fixit import FixItClient
from lib.mde import MDEClient
from lib.utils import get_secret

logger = logging.getLogger(__name__)


bp = func.Blueprint()


@bp.timer_trigger(
    schedule="0 0 6 * * 1-5",
    arg_name="myTimer",
    run_on_startup=False,
    use_monitor=True,
)
def ddc2_automation(myTimer: func.TimerRequest) -> None:
    """
    This is the main Azure Function that takes care of the Data Defender Cleanup task 2.
    For detailed description of what this does refer to the README.md.

    Actions:
        - Removes closed FixIt tags from devices.
    """

    if myTimer.past_due:
        logger.warning("The timer is past due!")

    # SETUP - start

    logger.info("Started the Data Defender Cleanup task 2.")

    try:
        key_vault_name = os.environ["KEY_VAULT_NAME"]
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
        credential=DefaultAzureCredential(),
    )

    # MDE secrets
    MDE_TENANT = get_secret(secret_client, "Azure-MDE-Tenant")
    MDE_CLIENT_ID = get_secret(secret_client, "Azure-MDE-Client-ID")
    MDE_SECRET_VALUE = get_secret(secret_client, "Azure-MDE-Secret-Value")

    # FixIt secrets
    FIXIT_4ME_ACCOUNT = get_secret(secret_client, "FixIt-4Me-Account")
    FIXIT_4ME_BASE_URL = get_secret(secret_client, "FixIt-4Me-Base-URL")
    FIXIT_4ME_API_KEY = get_secret(secret_client, "FixIt-4Me-API-Key")

    mde_client = MDEClient(MDE_TENANT, MDE_CLIENT_ID, MDE_SECRET_VALUE)
    fixit_client = FixItClient(FIXIT_4ME_BASE_URL, FIXIT_4ME_ACCOUNT, FIXIT_4ME_API_KEY)

    # SETUP - end

    devices = mde_client.get_devices()
    if not devices:
        logger.info("Task won't continue as there is no devices to process.")
        return

    logger.info(
        "Start removing FixIt tags that reference a completed request from devices in the Microsoft Defender portal."
    )

    removed_fixit_tags = 0

    for device in devices:
        if device.should_skip("DDC2"):
            continue

        if device.tags is None:
            logger.warning(f"Skipping {device} since it has no tags.")
            continue

        for tag in device.tags:
            request_id = FixItClient.extract_id(tag)

            if not request_id:
                continue

            request_status = fixit_client.get_request_status(request_id)

            if request_status == "completed":
                if mde_client.alter_device_tag(device, tag, "Remove"):
                    removed_fixit_tags += 1

    logger.info(
        f"Finished removing {removed_fixit_tags} Fix-It tags from devices in the Microsoft Defender portal."
    )
