"""
DDC3 Azure function.

This module features the Azure function that takes care of the
Data Defender cleanup task 3. This means it cleans up duplicate
devices by giving them a "ZZZ" tag.
"""

import logging
import os
import re

import azure.functions as func
from azure.identity import DefaultAzureCredential

from mde_fixit_integration.lib.mde import MDEClient, MDEDevice
from mde_fixit_integration.lib.utils import create_environment

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
    DDC3 Automation.

    For a detailed description of what this does refer to the README.md.

    Actions:
        - Adds "ZZZ" tag to duplicate devices.
    """
    if myTimer.past_due:
        logger.warning("The timer is past due for DDC3!")
        return

    # SETUP - start

    logger.info("starting the DDC3 automation")

    create_environment(DefaultAzureCredential())

    mde_client = MDEClient(
        os.environ["AZURE_MDE_TENANT"],
        os.environ["AZURE_MDE_CLIENT_ID"],
        os.environ["AZURE_MDE_SECRET_VALUE"],
    )

    # SETUP - end

    devices = mde_client.get_devices(
        odata_filter="(computerDnsName ne null) and (isExcluded eq false)",
    )
    if not devices:
        logger.info("won't continue as there is no devices to process")
        return

    logger.info('adding "ZZZ" tag to duplicate devices in the MDE')

    device_dict: DeviceDict = create_device_dict(devices)

    # Remove devices that only appear once (by name) in the table.
    remove_non_duplicates(device_dict)

    duplicate_devices_tagged = 0

    for devices in device_dict.values():
        for device in devices:
            if len(list(filter(is_zzz_tag, device.tags))) > 0:
                logger.debug(f"{device} already tagged or is not inactive. Skipping...")
                continue

            if device.health != "Inactive":
                logger.debug(f"{device} is not inactive ({device.health}). Skipping...")
                continue

            if mde_client.alter_device_tag(device, "ZZZ", "Add"):
                duplicate_devices_tagged += 1

    logger.info(f"finished tagging {duplicate_devices_tagged} devices")


def is_zzz_tag(tag: str) -> bool:
    """
    Tell wether a tag is a "ZZZ" tag or not.

    Parameters
    ----------
    tag : str:
            The string that represents the tag.

    Returns
    -------
    bool:
        True if the tag is a "ZZZ" tag.

    """
    return re.fullmatch(r"(?i)^z{3}$", tag) is not None


def create_device_dict(devices: list[MDEDevice]) -> DeviceDict:
    """
    Create a duplicate device dict.
    
    Create a dictionary from the given list of devices where
    each key in the dictionary, is the name of the device.

    Parameters
    ----------
    devices : list[MDEDevice]:
        The list of MDE devices.

    Returns
    -------
    DeviceDict:
        The dictionary containing all the MDE devices.

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
    Remove non duplicate devices from a device dictionary.
    
    This make sure that only devices that appear once (by name)
    is removed from the list.

    Parameters
    ----------
    device_dict : DeviceDict:
        The dictionary containing the devices.

    """
    for device_name, devices in list(device_dict.items()):
        if len(devices) == 1:
            del device_dict[device_name]
