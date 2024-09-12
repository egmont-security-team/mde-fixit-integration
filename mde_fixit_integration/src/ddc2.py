"""
This module contains the Azure function that takes care of the
Data Defender cleanup task 2. This means it removes FixIt tags
from devices where the relative request is completed.
"""

import logging
import os

import azure.functions as func
from azure.identity import DefaultAzureCredential

from mde_fixit_integration.lib.fixit import FixItClient
from mde_fixit_integration.lib.mde import MDEClient
from mde_fixit_integration.lib.utils import create_environment

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
        logger.warning("The timer is past due for DDC2!")
        return

    # SETUP - start

    logger.info("Started the Data Defender Cleanup task 2.")

    create_environment(DefaultAzureCredential())

    mde_client = MDEClient(
        os.environ["AZURE_MDE_TENANT"],
        os.environ["AZURE_MDE_CLIENT_ID"],
        os.environ["AZURE_MDE_SECRET_VALUE"],
    )
    fixit_client = FixItClient(
        os.environ["FIXIT_4ME_BASE_URL"],
        os.environ["FIXIT_4ME_ACCOUNT"],
        os.environ["FIXIT_4ME_API_KEY"],
    )

    # SETUP - end

    devices = mde_client.get_devices(
        odata_filter="(computerDnsName ne null) and (isExcluded eq false)"
    )
    if not devices:
        logger.info("Task won't continue as there is no devices to process.")
        return

    logger.info("Start removing FixIt tags that reference a completed request from devices in the Microsoft Defender portal.")

    request_status_cache: dict[str, str] = {}

    removed_fixit_tags = 0

    for device in devices:
        if device.should_skip("DDC2"):
            continue

        for tag in device.tags:
            request_id = FixItClient.extract_id(tag)

            if not request_id:
                continue

            if request_id not in request_status_cache:
                request_status = fixit_client.get_request_status(request_id)
                if request_status is None:
                    logger.warning(f"Failed to fetch the status of the Fix-It request #{request_id} for {device}.")
                    continue
                request_status_cache[request_id] = request_status

            request_status = request_status_cache[request_id]
            if request_status == "completed":
                if mde_client.alter_device_tag(device, tag, "Remove"):
                    removed_fixit_tags += 1

    logger.info(f"Finished removing {removed_fixit_tags} Fix-It tags from devices in the Microsoft Defender portal.")
