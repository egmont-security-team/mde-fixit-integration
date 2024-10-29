"""Utility functions used by multiple scripts."""

import logging
import os
import re
from typing import Optional

from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

logger = logging.getLogger(__name__)


def get_secret(
    secret_client: SecretClient, secret_name: str, env_var: Optional[str] = None,
) -> str:
    """
    Get a secret from Azure Key Vault.

    Parameters
    ----------
    secret_client : SecretClient
        The client to interact with the Azure Key Vault.
    secret_name : str
        The name of the secret to get.
    env_var : Optional[str]
        The name of the environment variable to hold secret.

    Returns
    -------
    str
        The value of the secret.

    Raises
    ------
    ValueError
        If the secret is not found in the key vault.

    """
    secret = secret_client.get_secret(secret_name)

    if secret.value is None:
        raise ValueError(f'Secret "{secret_name}" not found in the key vault.')

    if env_var:
        os.environ[env_var] = secret.value

    return secret.value


def create_environment(credential: DefaultAzureCredential) -> None:
    """
    Create the environment variables from the secrets in the key vault.

    Parameters
    ----------
    credential : DefaultAzureCredential
        The credential to authenticate with.

    """
    try:
        key_vault_name = os.environ["KEY_VAULT_NAME"]
    except KeyError:
        logger.critical(
            """
            did not find valid value for environment variable \"KEY_VAULT_NAME\";
            please set this in 
                \"local.settings.json\"
            or in
                \"application settings\"
            in Azure.
            """,
        )
        return

    sc = SecretClient(
        vault_url=f"https://{key_vault_name}.vault.azure.net",
        credential=credential,
    )

    # MDE secrets
    get_secret(sc, "Azure-MDE-Tenant", env_var="AZURE_MDE_TENANT")
    get_secret(sc, "Azure-MDE-Client-ID", env_var="AZURE_MDE_CLIENT_ID")
    get_secret(sc, "Azure-MDE-Secret-Value", env_var="AZURE_MDE_SECRET_VALUE")

    # FixIt secrets
    get_secret(sc, "FixIt-4Me-Base-URL", env_var="FIXIT_4ME_BASE_URL")
    get_secret(sc, "FixIt-4Me-Account", env_var="FIXIT_4ME_ACCOUNT")
    get_secret(sc, "FixIt-4Me-API-Key", env_var="FIXIT_4ME_API_KEY")

    get_secret(sc, "CVE-Single-FixIt-Template-ID", env_var="FIXIT_SINGLE_TEMPLATE_ID")
    get_secret(sc, "CVE-Multi-FixIt-Template-ID", env_var="FIXIT_MULTI_TEMPLATE_ID")
    get_secret(sc, "CVE-Service-Instance-ID", env_var="FIXIT_SERVICE_INSTANCE_ID")
    get_secret(sc, "CVE-SD-Team-ID", env_var="FIXIT_SD_TEAM_ID")
    get_secret(sc, "CVE-MW-Team-ID", env_var="FIXIT_MW_TEAM_ID")
    get_secret(sc, "CVE-SEC-Team-ID", env_var="FIXIT_SEC_TEAM_ID")
    get_secret(sc, "CVE-CAD-Team-ID", env_var="FIXIT_CAD_TEAM_ID")


def get_cve_from_str(string: str) -> Optional[str]:
    """
    Get a CVE from a string.

    Gets the first CVE from a given string (if it has a CVE tag).
    This uses regular expression to find the first CVE tag in the string.

    Parameters
    ----------
    string : str
        The string to extract the CVE from.

    Returns
    -------
    str
        The CVE from the tag.
    
    """
    if cve := re.findall(r"CVE-\d{4}-\d{4,7}", string):
        return cve[0]
    return None
