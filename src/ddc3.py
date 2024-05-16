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
    use_monitor=True,
)
def ddc3_automation(myTimer: func.TimerRequest) -> None:
    """
    This is the main Azure Function that takes care of the Data Defender Cleanup task 3.
    For detailed description of what this does refer to the README.md.

    Actions:
        - Adds "ZZZ" tag to duplicate devices.
    """

    # SETUP - start

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
        vault_url=f"https://{key_vault_name}.vault.azure.net",
        credential=credential,
    )

    # MDE secrets
    MDE_TENANT = secret_client.get_secret("Azure-MDE-Tenant").value
    MDE_CLIENT_ID = secret_client.get_secret("Azure-MDE-Client-ID").value
    MDE_SECRET_VALUE = secret_client.get_secret("Azure-MDE-Secret-Value").value

    mde_client: MDEClient = MDEClient(MDE_TENANT, MDE_CLIENT_ID, MDE_SECRET_VALUE)

    # SETUP - end

    devices = mde_client.get_devices()

    if not devices:
        logger.info("Task won't continue as there is no devices to process.")
        return

    device_dict: dict[str, MDEDevice] = create_device_dict(devices)

    # Remove devices that only appear once (by name) in the table.
    remove_non_duplicates(device_dict)

    logger.info(
        'Start adding "ZZZ" tag to duplicate devices in the Microsoft Defender portal.'
    )

    duplicate_devices_tagged = 0

    for device_name, devices in device_dict.items():
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

    params:
        tag:
            str: The string that represents the tag.

    returns:
        bool: True if the tag is a "ZZZ" tag.
    """

    return re.match(r"(?i)^z{3}$", tag)


def create_device_dict(devices: list[MDEDevice]) -> dict[str, MDEDevice]:
    """
    Creates a dictionary from the given list of devices where each key
    in the dictionary, is the name of the device.

    params:
        devices:
            list[MDEDevice]: The list of MDE devices.

    returns:
        dict[str, MDEDevice]: The dictionary containing all the MDE devices.
    """
    device_dict: dict[str, MDEDevice] = {}

    for device in devices:
        if device.should_skip("DDC3"):
            continue

        # This is later used to determine if the devices are duplicates.
        if device_dict.get(device.name) is None:
            device_dict[device.name] = [device]
        else:
            device_dict[device.name].append(device)
        
    return device_dict


def remove_non_duplicates(device_dict: dict[str, MDEDevice]):
    """
    Removes non duplicate devices from a device dictionary. This make sure
    that only devices that appear once (by name) is removed from the list.

    params:
        device_dict:
            dict[str, MDEDevice]: The dictionary containing the devices.
    """
    for device_name, devices in list(device_dict.items()):
        if len(devices) == 1:
            del device_dict[device_name]
