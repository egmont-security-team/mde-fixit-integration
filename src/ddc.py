import logging
import azure.functions as func

bp = func.Blueprint()


@bp.timer_trigger(
    schedule="0 0 8 * * 1-5",
    arg_name="myTimer",
    run_on_startup=False,
    use_monitor=False,
)
def ddc_automation(myTimer: func.TimerRequest) -> None:
    test_logging("test")

def test_logging():
    logging.info("test")
