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


bp = func.Blueprint()


@bp.timer_trigger(
    schedule="0 0 8,14 * * 1-5",
    arg_name="myTimer",
    run_on_startup=False,
    use_monitor=False,
)
def ddc3_automation(myTimer: func.TimerRequest) -> None:
    """
    This is the main Azure Function that takes care of the Data Defender Cleanup task 3.
    For detailed description of what this does refer to the README.md.

    Actions:
        - Adds "ZZZ" tag to duplicate devices.
    """

    logger.info("Started the Data Defender Cleanup task 3.")

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

    mde_client: MDEClient = MDEClient(MDE_TENANT, MDE_CLIENT_ID, MDE_SECRET_VALUE)

    devices = mde_client.get_devices()
    devices_sorted_by_name: dict(str, MDEDevice) = {}

    if not devices:
        logger.info("Task won't continue as there is no devices to process.")
        return

    for device in devices:
        if device.should_skip(automations=["DDC3"]):
            continue

        # This is later used to determine if the devices are duplicates.
        if devices_sorted_by_name.get(device.name) is None:
            devices_sorted_by_name[device.name] = [device]
        else:
            devices_sorted_by_name[device.name].append(device)

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
        "Finished tagging {} duplicate devices in the Microsoft Defender portal.".format(
            duplicate_devices_tagged
        )
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
