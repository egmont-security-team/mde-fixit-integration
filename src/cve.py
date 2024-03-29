"""
This module contains the Azure function that takes care of
the CVE related stuff. This means creating FixIt tickets for devices
hit by certain CVE's.
"""

import azure.functions as func

from src.logging import logger

bp = func.Blueprint()


@bp.timer_trigger(
    schedule="0 0 8 * * 1-5",
    arg_name="myTimer",
    run_on_startup=False,
    use_monitor=False,
)
def cve_automation(myTimer: func.TimerRequest) -> None:
    """
    TODO: This function is WIP.
    """
    logger.info("CVE cleanup task has started")
