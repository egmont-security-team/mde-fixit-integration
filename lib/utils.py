"""
Utility functions used by multiple scripts.
"""

import os
import logging
from typing import Optional

from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

logger = logging.getLogger(__name__)


def get_secret(
    secret_client: SecretClient, secret_name: str, env_var: Optional[str] = None
) -> str:
    """
    Get a secret from Azure Key Vault.

    params:
        secret_client:
            SecretClient: The client to interact with the Azure Key Vault.
        secret_name:
            str: The name of the secret to get.

    returns:
        str: The value of the secret.
    """
    secret = secret_client.get_secret(secret_name)

    if secret.value is None:
        raise ValueError(f'Secret "{secret_name}" not found in the key vault.')

    if env_var:
        os.environ[env_var] = secret.value

    return secret.value


def create_environment(key_vault_name: str, credential: DefaultAzureCredential) -> None:
    """
    Create the environment variables from the secrets in the key vault.

    params:
        key_vault_name:
            str: The name of the key vault.
        credential:
            DefaultAzureCredential: The credential to authenticate with the key vault.
    """
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
    get_secret(sc, "CVE-CLOUD-Team-ID", env_var="FIXIT_CLOUD_TEAM_ID")
