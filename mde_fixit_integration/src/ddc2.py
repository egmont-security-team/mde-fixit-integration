"""
DDC2 Azure function.

This module features the Azure function responsible for handling
Data Defender Cleanup Task 2. Specifically, it removes FixIt tags
from devices once their associated requests are completed.
"""

__copyright__ = "Copyright (C) 2024 Egmont IT"

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
def ddc2_automation(myTimer: func.TimerRequest) -> None:  # noqa: N803
    """
    DDC2 automation.

    This is the main Azure function that takes care of the
    Data Defender Cleanup task 2. For detailed description
    of what this does refer to the README.md.

    Actions:
        - Removes tags from devices associated with a closed ticket.
    """
    if myTimer.past_due:
        logger.warning("timer is past due for DDC2!")
        return

    # SETUP - start

    logger.info("starting the DDC2 automation")

    create_environment(DefaultAzureCredential())

    mde_client = MDEClient(
        os.environ["AZURE_MDE_TENANT"],
        os.environ["AZURE_MDE_CLIENT_ID"],
        os.environ["AZURE_MDE_SECRET_VALUE"],
    )
    fixit_client = FixItClient(
        os.environ["XURRENT_BASE_URL"],
        os.environ["XURRENT_ACCOUNT"],
        os.environ["XURRENT_API_KEY"],
    )

    # SETUP - end

    devices = mde_client.get_devices(
        odata_filter="(computerDnsName ne null) and (isExcluded eq false)",
    )
    if not devices or len(devices) < 1:
        logger.critical("task won't continue as there is no devices to process")
        return

    request_status_cache: dict[str, str] = {}

    removed_tags = 0

    for device in devices:
        if device.should_skip("DDC2"):
            continue

        for tag in device.tags:
            request_id = FixItClient.extract_id(tag)

            if not request_id:
                continue

            if request_id not in request_status_cache:
                if request_status_cache.get(request_id):
                    continue

                request_status = fixit_client.get_request_status(request_id)
                if request_status is None:
                    logger.warning(
                        f"failed to fetch the status of the ticket #{request_id}",
                        extra={
                            "device": str(device),
                            "fixit_id": request_id,
                        },
                    )
                    continue

                request_status_cache[request_id] = request_status

            request_status = request_status_cache[request_id]
            if request_status != "completed":
                continue

            if mde_client.alter_device_tag(device, tag, "Remove"):
                removed_tags += 1

    logger.info(f"finished removing {removed_tags} tags from devices")
