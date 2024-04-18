"""
This module contains the Azure function that takes care of
the CVE related stuff. This means creating FixIt tickets for devices
hit by certain CVE's.
"""

import os

import azure.functions as func
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

from lib.logging import logger
from lib.mde import MDEClient, MDEDevice
from lib.fixit import FixItClient


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

    logger.info("Started the CVE Automation tasks.")

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
        vault_url="https://{}.vault.azure.net".format(key_vault_name),
        credential=credential,
    )

    # MDE secrets
    MDE_TENANT = secret_client.get_secret("Azure-MDE-Tenant").value
    MDE_CLIENT_ID = secret_client.get_secret("Azure-MDE-Client-ID").value
    MDE_SECRET_VALUE = secret_client.get_secret("Azure-MDE-Secret-Value").value

    # FixIt secrets
    FIXIT_4ME_ACCOUNT = secret_client.get_secret("FixIt-4Me-Account").value
    FIXIT_4ME_BASE_URL = secret_client.get_secret("FixIt-4Me-Base-URL").value
    FIXIT_4ME_API_KEY = secret_client.get_secret("FixIt-4Me-API-Key").value

    mde_client: MDEClient = MDEClient(MDE_TENANT, MDE_CLIENT_ID, MDE_SECRET_VALUE)
    fixit_client: FixItClient = FixItClient(
        FIXIT_4ME_ACCOUNT, FIXIT_4ME_BASE_URL, FIXIT_4ME_API_KEY
    )

    high_cve_tabel = {}
    critical_cve_tabel = {}

    devices = mde_client.get_devices()

    if not devices:
        logger.info("Task won't continue as there is no devices to process.")
        return

    for device in devices:
        continue
