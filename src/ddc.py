import logging
import requests
import azure.functions as func

bp = func.Blueprint()

KEY_VAULT = ""


@bp.timer_trigger(
    schedule="0 0 8 * * Mon-Fri",
    arg_name="myTimer",
    run_on_startup=True,
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

    token: str = get_mde_token()
    devices: list = get_devices(token)

    if not devices:
        logging.error("No devices found to check.")

    for device in devices:
        continue


def get_mde_token() -> str:
    """
    Autheticates with Azure to get a new API key for the Defender Portal.

    returns:
        str: The bearer token that grants authorization for the Defender Portal API.
    """

    return "token"


def get_devices(token: str) -> list:
    """
    Gets a list of all devices from the Microsoft Defender portal.
    This might takes multiples requests because the Microsoft Defender API
    only allows to fetch 10K devices at a time.

    returns:
        list: The machines from the Defender Portal API.
    """

    devices_url = "https://api.securitycenter.microsoft.com/api/machines?$filter=computerDnsName%20ne%20null"
    devices = []

    while devices_url:
        res = requests.get(devices_url, headers={"Authorization": f"Bearer {token}"})

        status_code: int = res.status_code
        body = res.json()

        if status_code != 200:
            log_props = {
                "custom_dimensions": {
                    "status": status_code,
                    "content": res.content,
                }
            }
            logging.error("Failed to fetch devices.", extra=log_props)
            break

        # Get the new devices from the request.
        new_devices = body.get("value")
        logging.info(f"Got {len(new_devices)} new devices.")

        devices += new_devices

        # The Microsoft Defender API has a limit of 10k devices per request.
        # In case this URL exsist, this means that more devices can be fetched.
        # This URL given here can be used to fetch the next devices.
        devices_url = body.get("@odata.nextLink")

    logging.info(f"Got a total of {len(devices)} devices from Defender Portal API.")

    return devices
