"""
This module contains the Azure function that takes care of the
Data Defender cleanup task 3. This means it cleans up duplicate
devices by giving them a "ZZZ" tag.
"""

import logging
import os
import re

import azure.functions as func
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

from lib.mde import MDEClient, MDEDevice
from lib.utils import get_secret

DeviceDict = dict[str, list[MDEDevice]]

logger = logging.getLogger(__name__)


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

    For a detailed description of what this does refer to the README.md.

    Actions:
        - Adds "ZZZ" tag to duplicate devices.
    """

    if myTimer.past_due:
        logger.warning("The timer is past due!")

    # SETUP - start

    logger.info("Started the Data Defender Cleanup task 3.")

    try:
        key_vault_name: str = os.environ["KEY_VAULT_NAME"]
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

    # Microsoft Defender for Endpoint secrets
    MDE_TENANT = get_secret(secret_client, "Azure-MDE-Tenant")
    MDE_CLIENT_ID = get_secret(secret_client, "Azure-MDE-Client-ID")
    MDE_SECRET_VALUE = get_secret(secret_client, "Azure-MDE-Secret-Value")

    mde_client = MDEClient(MDE_TENANT, MDE_CLIENT_ID, MDE_SECRET_VALUE)

    # SETUP - end

    devices = mde_client.get_devices()
    if not devices:
        logger.info("Task won't continue as there is no devices to process.")
        return

    logger.info(
        'Start adding "ZZZ" tag to duplicate devices in the Microsoft Defender portal.'
    )

    device_dict: DeviceDict = create_device_dict(devices)

    # Remove devices that only appear once (by name) in the table.
    remove_non_duplicates(device_dict)

    duplicate_devices_tagged = 0

    for devices in device_dict.values():
        for device in devices:
            if len(list(filter(is_zzz_tag, device.tags))) > 0:
                logger.debug(f"{device} already tagged or not inactive, skipping...")
                continue

            if device.health != "Inactive":
                logger.debug(f"{device} is not inactive ({device.health}), skipping...")
                continue

            if mde_client.alter_device_tag(device, "ZZZ", "Add", sleep=0.5):
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
    return re.fullmatch(r"(?i)^z{3}$", tag) is not None


def create_device_dict(devices: list[MDEDevice]) -> DeviceDict:
    """
    Creates a dictionary from the given list of devices where each key
    in the dictionary, is the name of the device.

    params:
        devices:
            list[MDEDevice]: The list of MDE devices.

    returns:
        dict[str, MDEDevice]: The dictionary containing all the MDE devices.
    """
    device_dict: DeviceDict = {}

    for device in devices:
        if device.should_skip("DDC3"):
            continue

        if device.name is None:
            continue

        # This is later used to determine if the devices are duplicates.
        if device_dict.get(device.name) is None:
            device_dict[device.name] = [device]
        else:
            device_dict[device.name].append(device)

    return device_dict


def remove_non_duplicates(device_dict: DeviceDict):
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
