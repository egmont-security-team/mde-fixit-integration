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

    #token: str = get_mde_token(AZURE_TENANT, AZURE_MDE_CLIENT_ID, AZURE_MDE_SECRET_VALUE)
    #devices: list = get_devices(token)

    #if not devices:
    #    logging.info("Task won't continue as there is no devices to process.")
    #    return

    #for device in devices:
    #    continue

'''
def get_mde_token(tenant: str, client_id: str, secret_value: str) -> str | None:
    """
    Autheticates with Azure to get a new API key for the Defender Portal.

    returns:
        str: The bearer token that grants authorization for the Defender Portal API.
        None: Returns `None` when it fails to get the desired authorization token.
    """

    res = requests.post(
        f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
        data={
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": secret_value,
            "scope": "https://api-eu.securitycenter.microsoft.com/.default",
        },
    )

    status_code = res.status_code
    json = res.json()

    if status_code != 200:
        custom_dimensions = {"status": status_code, "json": json}
        logging.error(
            "Couldn't get Microsoft Defender token from Microsoft authetication flow",
            extra={"custom_dimensions": custom_dimensions},
        )
        return

    token = json.get("access_token")

    if not token:
        custom_dimensions = {"status": status_code, "json": json}
        logging.error(
            "The Microsoft Defender token was not provided in the request even tho is was succelsful",
            extra={"custom_dimensions": custom_dimensions},
        )

    return token



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
        json = res.json()

        if status_code != 200:
            custom_dimensions = {
                "status": status_code,
                "content": res.content,
            }
            logging.error(
                "Failed to fetch devices from Microsoft Defender API.",
                extra={"custom_dimensions": custom_dimensions},
            )
            break

        # Get the new devices from the request.
        new_devices = json.get("value")
        logging.info(
            f"Fetched {len(new_devices)} new devices from Microsoft Defender API."
        )

        devices += new_devices

        # The Microsoft Defender API has a limit of 10k devices per request.
        # In case this URL exsist, this means that more devices can be fetched.
        # This URL given here can be used to fetch the next devices.
        devices_url = json.get("@odata.nextLink")

    logging.info(
        f"Fetched a total of {len(devices)} devices from Microsoft Defender API."
    )

    return devices
'''