import logging
import requests
import azure.functions as func

bp = func.Blueprint()


@bp.timer_trigger(
    schedule="0 0 8 * * Mon-Fri",
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

    logging.info("Started the Data Defender Cleanup task!")

    AZURE_TENANT = "000-000-000-000"
    AZURE_MDE_CLIENT_ID = "000-000-000-000"
    AZURE_MDE_SECRET_VALUE = "000-000-000-000"


