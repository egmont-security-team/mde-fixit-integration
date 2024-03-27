import logging 
import azure.functions as func 

bp = func.Blueprint() 

@bp.timer_trigger(
    schedule="* */10 * * * *",
    arg_name="myTimer",
    run_on_startup=False,
    use_monitor=False,
) 
def ddc_automation(myTimer: func.TimerRequest) -> None: 
    logging.info("Hello from DDC")
