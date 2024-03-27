import logging
import azure.functions as func

bp = func.Blueprint()


@bp.timer_trigger(
    schedule="0 0 8 * * Mon-Fri",
    arg_name="myTimer",
    run_on_startup=False,
    use_monitor=False,
)
def cve_automation(myTimer: func.TimerRequest) -> None:
    logging.info("CVE cleanup task has started.")
