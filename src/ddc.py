"""
This module contains the Azure function that takes care of the
Data Defender cleanup tasks. This means it cleans up duplicate
devices and removes FixIt tags that has the relative request completed.
"""

import re
import os

import azure.functions as func
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
import requests

from src.logging import logger
from src.shared import (
    get_fixit_request_id_from_tag,
    get_fixit_request_status,
    alter_device_tag,
)


bp = func.Blueprint()


@bp.timer_trigger(
    schedule="0 0 8 * * 1-5",
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

    logger.info("Started the Data Defender Cleanup tasks.")

    credential = DefaultAzureCredential()
    key_vault_name = os.environ["KEY_VAULT_NAME"]

    if not key_vault_name:
        logger.critical(
            """
            Did not find environment variable \"KEY_VAULT_NAME\". Please set this 
            in \"local.settings.json\" or in the application settings in Azure.
            """
        )
        return

    secret_client = SecretClient(
        vault_url=f"https://{key_vault_name}.vault.azure.net", credential=credential
    )

    # MDE secrets
    AZURE_MDE_TENANT = secret_client.get_secret("Azure-MDE-Tenant").value
    AZURE_MDE_CLIENT_ID = secret_client.get_secret("Azure-MDE-Client-ID").value
    AZURE_MDE_SECRET_VALUE = secret_client.get_secret("Azure-MDE-Secret-Value").value
    if not AZURE_MDE_TENANT or not AZURE_MDE_CLIENT_ID or not AZURE_MDE_SECRET_VALUE:
        custom_dimensions = {
            "AZURE_MDE_TENANT": "set" if AZURE_MDE_TENANT else "missing",
            "AZURE_MDE_CLIENT_ID": "set" if AZURE_MDE_CLIENT_ID else "missing",
            "AZURE_MDE_SECRET_VALUE": "set" if AZURE_MDE_SECRET_VALUE else "missing",
        }
        logger.critical(
            "Missing some of Azure MDE secrets from the key vault. Please add them or the function can't run.",
            extra={"custom_dimensions": custom_dimensions},
        )
        return

    # FixIt secrets
    FIXIT_4ME_BASE_URL = secret_client.get_secret("FixIt-4Me-Base-URL").value
    FIXIT_4ME_ACCOUNT = secret_client.get_secret("FixIt-4Me-Account").value
    FIXIT_4ME_API_KEY = secret_client.get_secret("FixIt-4Me-API-Key").value
    if not FIXIT_4ME_ACCOUNT or not FIXIT_4ME_API_KEY:
        custom_dimensions = {
            "FIXIT_4ME_BASE_URL": "set" if FIXIT_4ME_ACCOUNT else "missing",
            "FIXIT_4ME_ACCOUNT": "set" if FIXIT_4ME_ACCOUNT else "missing",
            "FIXIT_4ME_API_KEY": "set" if FIXIT_4ME_API_KEY else "missing",
        }
        logger.critical(
            "Missing FixIt 4Me secrets from key vault. Please add them or the function can't run.",
            extra={"custom_dimensions": custom_dimensions},
        )
        return

    mde_token = get_mde_token(
        AZURE_MDE_TENANT, AZURE_MDE_CLIENT_ID, AZURE_MDE_SECRET_VALUE
    )
    devices = get_devices(mde_token)

    if not devices:
        logger.info("Task won't continue as there is no devices to process.")
        return

    devices_sorted_by_name = {}

    logger.info(
        "Start removing FixIt tags that reference a completed request from devices in the Microsoft Defender portal."
    )

    removed_fixit_tags = 0

    for device in devices:
        device_id = device.get("id")
        device_tags = device.get("machineTags")
        device_name = device.get("computerDnsName")
        device_health = device.get("healthStatus")
        device_object = {
            "id": device_id,
            "name": device_name,
            "tags": device_tags,
            "health": device_health,
        }

        # This is later used to determine if the devices are duplicates.
        if devices_sorted_by_name.get(device_name) is None:
            devices_sorted_by_name[device_name] = [device_object]
        else:
            devices_sorted_by_name[device_name].append(device_object)

        for tag in device_tags:
            request_id = get_fixit_request_id_from_tag(tag)

            if not request_id:
                continue

            request_status = get_fixit_request_status(
                request_id, FIXIT_4ME_BASE_URL, FIXIT_4ME_ACCOUNT, FIXIT_4ME_API_KEY
            )

            if request_status == "completed":
                if alter_device_tag(mde_token, device_id, tag, "Remove", device_name=device_name):
                    removed_fixit_tags += 1

    logger.info(
        f"Finished removing {removed_fixit_tags} Fix-It tags from devices in the Microsoft Defender portal."
    )

    # Remove devices that only appear once (by name) in the table.
    for device_name, devices in list(devices_sorted_by_name.items()):
        if len(devices) == 1:
            del devices_sorted_by_name[device_name]

    logger.info(
        'Start adding "ZZZ" tag to duplicate devices in the Microsoft Defender portal.'
    )

    duplicate_devices_tagged = 0

    for device_name, devices in devices_sorted_by_name.items():
        for index, device in enumerate(devices):
            device_id = device.get("id")
            device_tags = device.get("tags")
            device_health = device.get("health")

            # If it already have the ZZZ or it isn't inactive, skip it
            if not len(list(filter(is_zzz_tag, device_tags))) or device_health != "Inactive":
                continue

            if alter_device_tag(mde_token, device_id, "ZZZ", "Add", device_name=device_name):
                duplicate_devices_tagged += 1

    logger.info(
        f"Finished tagging {duplicate_devices_tagged} duplicate devices in the Microsoft Defender portal."
    )


def get_mde_token(tenant: str, client_id: str, secret_value: str) -> str:
    """
    Authenticates with Azure to get a new API key for the Microsoft Defender Portal.

    params:
        tenant:
            str: The tenant of the Microsoft Defender environment.
        client_id:
            str: The ID of the Microsoft Defender app in Azure.
        secret_value:
            str: The secret value of the Microsoft Defender app in Azure.

    returns:
        str: The bearer token that grants authorization for the Defender Portal API.
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
        custom_dimensions = {"status": status_code, "body": res.content}
        logger.error(
            "Couldn't get Microsoft Defender token from Microsoft authentication flow.",
            extra={"custom_dimensions": custom_dimensions},
        )
        return ""

    token = json.get("access_token")

    if not token:
        custom_dimensions = {"status": status_code, "body": res.content}
        logger.error(
            "The Microsoft Defender token was not provided in the request even tho it is was successful.",
            extra={"custom_dimensions": custom_dimensions},
        )

    return token


def get_devices(token: str) -> list:
    """
    Gets a list of all devices from the Microsoft Defender portal.
    This might takes multiples requests because the Microsoft Defender API
    only allows to fetch 10K devices at a time.

    params:
        token:
            str: The bearer token for authorizing with the Microsoft Defender API.

    returns:
        list: The machines from the Defender Portal API.
    """

    devices_url = "https://api.securitycenter.microsoft.com/api/machines?$filter=(computerDnsName ne null) and (isExcluded eq false)"
    devices = []

    while devices_url:
        res = requests.get(devices_url, headers={"Authorization": f"Bearer {token}"})

        status_code = res.status_code
        json = res.json()

        if status_code != 200:
            custom_dimensions = {"status": status_code, "body": res.content}
            logger.error(
                "Failed to fetch devices from Microsoft Defender API.",
                extra={"custom_dimensions": custom_dimensions},
            )
            break

        # Get the new devices from the request.
        new_devices = json.get("value")
        logger.info(
            f"Fetched {len(new_devices)} new devices from Microsoft Defender API."
        )

        devices += new_devices

        # The Microsoft Defender API has a limit of 10k devices per request.
        # In case this URL exists, this means that more devices can be fetched.
        # This URL given here can be used to fetch the next devices.
        devices_url = json.get("@odata.nextLink")

    logger.info(
        f"Fetched a total of {len(devices)} devices from Microsoft Defender API."
    )

    return devices


def is_zzz_tag(tag: str) -> bool:
    """
    This returns wether this is a "ZZZ" tag or not.

    returns:
        bool: True if the tag is a "ZZZ" tag.
    
    params:
        tag:
            str: The string that represents the tag.
    """
    return re.match(r"(?i)^z{3}$", tag)
