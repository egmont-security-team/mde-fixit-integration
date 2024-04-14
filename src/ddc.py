"""
This module contains the Azure function that takes care of the
Data Defender cleanup tasks. This means it cleans up duplicate
devices and removes FixIt tags that has the relative request completed.
"""

import re
import os

import azure.functions as func
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

from lib.logging import logger
from lib.mde import MDEClient, MDEDevice
from lib.fixit import FixItClient


bp = func.Blueprint()


@bp.timer_trigger(
    schedule="0 0 8 * * 1-5",
    arg_name="myTimer",
    run_on_startup=False,
    use_monitor=False,
)
def ddc_automation(myTimer: func.TimerRequest) -> None:
    """
    This is the main Azure Function that takes care of the Data Defender Cleanup tasks.
    For detailed description of what this does refer to the README.md.

    Actions:
        - Removes closed FixIt tags from devices.
        - Adds "ZZZ" tag to duplicate devices.
    """

    logger.info("Started the Data Defender Cleanup tasks.")

    credential = DefaultAzureCredential()
    key_vault_name = os.environ["KEY_VAULT_NAME"]

    if not key_vault_name:
        logger.critical(
            """
            Did not find environment variable \"KEY_VAULT_NAME\". Please set this 
            in \"local.settings.json\" or in the application settings in Azure.
            """
        )
        return

    secret_client = SecretClient(
        vault_url=f"https://{key_vault_name}.vault.azure.net", credential=credential
    )

    # MDE secrets
    AZURE_MDE_TENANT = secret_client.get_secret("Azure-MDE-Tenant").value
    AZURE_MDE_CLIENT_ID = secret_client.get_secret("Azure-MDE-Client-ID").value
    AZURE_MDE_SECRET_VALUE = secret_client.get_secret("Azure-MDE-Secret-Value").value

    # FixIt secrets
    FIXIT_4ME_ACCOUNT = secret_client.get_secret("FixIt-4Me-Account").value
    FIXIT_4ME_BASE_URL = secret_client.get_secret("FixIt-4Me-Base-URL").value
    FIXIT_4ME_API_KEY = secret_client.get_secret("FixIt-4Me-API-Key").value

    mde_client: MDEClient = MDEClient(
        AZURE_MDE_TENANT, AZURE_MDE_CLIENT_ID, AZURE_MDE_SECRET_VALUE
    )
    fixit_client = FixItClient(FIXIT_4ME_ACCOUNT, FIXIT_4ME_BASE_URL, FIXIT_4ME_API_KEY)

    devices = mde_client.get_devices()
    devices_sorted_by_name: dict(str, MDEDevice) = {}

    if not devices:
        logger.info("Task won't continue as there is no devices to process.")
        return

    logger.info(
        "Start removing FixIt tags that reference a completed request from devices in the Microsoft Defender portal."
    )

    removed_fixit_tags = 0

    for device_payload in devices:
        device = MDEDevice(
            device_payload.get("id"),
            name=device_payload.get("computerDnsName"),
            tags=device_payload.get("machineTags"),
            health=device_payload.get("healthStatus"),
        )

        # This is later used to determine if the devices are duplicates.
        if devices_sorted_by_name.get(device.name) is None:
            devices_sorted_by_name[device.name] = [device]
        else:
            devices_sorted_by_name[device.name].append(device)

        for tag in device.tags:
            request_id = fixit_client.extract_id(tag)

            if not request_id:
                continue

            request_status = fixit_client.get_request_status(request_id)

            if request_status == "completed":
                if mde_client.alter_device_tag(device, tag, "Remove"):
                    removed_fixit_tags += 1

    logger.info(
        f"Finished removing {removed_fixit_tags} Fix-It tags from devices in the Microsoft Defender portal."
    )

    # Remove devices that only appear once (by name) in the table.
    for device_name, devices in list(devices_sorted_by_name.items()):
        if len(devices) == 1:
            del devices_sorted_by_name[device_name]

    logger.info(
        'Start adding "ZZZ" tag to duplicate devices in the Microsoft Defender portal.'
    )

    duplicate_devices_tagged = 0

    for device_name, devices in devices_sorted_by_name.items():
        for index, device in enumerate(devices):
            # If it already have the ZZZ or it isn't inactive, skip it
            if (
                len(list(filter(is_zzz_tag, device.tags)))
                or device.health != "Inactive"
            ):
                continue

            if device.alter_device_tag("ZZZ", "Add"):
                duplicate_devices_tagged += 1

    logger.info(
        f"Finished tagging {duplicate_devices_tagged} duplicate devices in the Microsoft Defender portal."
    )


def is_zzz_tag(tag: str) -> bool:
    """
    This returns wether this is a "ZZZ" tag or not.

    returns:
        bool: True if the tag is a "ZZZ" tag.

    params:
        tag:
            str: The string that represents the tag.
    """
    return re.match(r"(?i)^z{3}$", tag)
