"""
This module contains the Azure function that takes care of
the CVE related stuff. This means creating FixIt tickets for devices
hit by certain CVE's.
"""

import os

import azure.functions as func
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
import requests

from lib.logging import logger
from lib.shared import (
    get_devices,
    get_mde_token,
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
def cve_automation(myTimer: func.TimerRequest) -> None:
    """
    TODO: This function is WIP.
    """

    logger.info("CVE cleanup task has started")

    credential = DefaultAzureCredential()

    try:
        key_vault_name = os.environ["KEY_VAULT_NAME"]
        if not key_vault_name:
            raise KeyError
    except KeyError:
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

    # FixIt secrets
    FIXIT_4ME_BASE_URL = secret_client.get_secret("FixIt-4Me-Base-URL").value
    FIXIT_4ME_ACCOUNT = secret_client.get_secret("FixIt-4Me-Account").value
    FIXIT_4ME_API_KEY = secret_client.get_secret("FixIt-4Me-API-Key").value

    mde_token = get_mde_token(
        AZURE_MDE_TENANT, AZURE_MDE_CLIENT_ID, AZURE_MDE_SECRET_VALUE
    )
    devices = get_devices(mde_token)

    high_cve_tabel = {}
    critical_cve_tabel = {}

    for device in devices:
        continue

