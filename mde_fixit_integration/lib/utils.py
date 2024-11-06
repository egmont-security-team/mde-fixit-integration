"""Utility functions used by multiple scripts."""

import logging
import os
import re
from typing import Optional

from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

logger = logging.getLogger(__name__)


def get_secret(
    secret_client: SecretClient, secret_name: str
) -> str:
    """
    Get a secret from Azure Key Vault.

    Parameters
    ----------
    secret_client : SecretClient
        The client to interact with the Azure Key Vault.
    secret_name : str
        The name of the secret to get.

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
        raise ValueError(f'missing secret {secret_name}; not found in key vault')

    env_var = secret_name.upper().replace("-", "_").replace(" ", "_")
    os.environ[env_var] = secret.value

    return secret.value


def create_environment(credential: DefaultAzureCredential) -> None:
    r"""
    Create the environment variables from the secrets in the key vault.

    Parameters
    ----------
    credential : DefaultAzureCredential
        The credential to authenticate with.
    
    Raises
    ------
    OSError
        If "KEY_VAULT_NAME" is not present in environment variables

    """
    try:
        key_vault_name = os.environ["KEY_VAULT_NAME"]
    except KeyError:
        raise OSError(
            """
            did not find valid value for environment variable \"KEY_VAULT_NAME\";
            please set this in 
                \"local.settings.json\"
            or in application settings in Azure.
            """,
        )

    sc = SecretClient(
        vault_url=f"https://{key_vault_name}.vault.azure.net",
        credential=credential,
    )

    # MDE secrets
    get_secret(sc, "Azure-MDE-Tenant")
    get_secret(sc, "Azure-MDE-Client-ID")
    get_secret(sc, "Azure-MDE-Secret-Value")

    # Xurrent secrets
    get_secret(sc, "Xurrent-Base-URL")
    get_secret(sc, "Xurrent-Account")
    get_secret(sc, "Xurrent-API-Key")

    get_secret(sc, "CVE-Single-Template-ID")
    get_secret(sc, "CVE-Multi-Template-ID")
    get_secret(sc, "CVE-Service-Instance-ID")
    get_secret(sc, "CVE-BIO-Service-Instance-ID")
    get_secret(sc, "CVE-SD-Team-ID")
    get_secret(sc, "CVE-MW-Team-ID")
    get_secret(sc, "CVE-SOC-Team-ID")
    get_secret(sc, "CVE-CAD-Team-ID")


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
