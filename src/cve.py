import logging 
import azure.functions as func 

bp = func.Blueprint() 

@bp.timer_trigger(
    schedule="* */5 * * * *",
    arg_name="myTimer",
    run_on_startup=False,
    use_monitor=False,
) 
def cve_automation(myTimer: func.TimerRequest) -> None: 
    logging.info("Hello from CVE")