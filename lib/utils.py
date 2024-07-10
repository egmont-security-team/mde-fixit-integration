"""
Utility functions used by multiple scripts.
"""

import logging
from azure.keyvault.secrets import SecretClient

logger = logging.getLogger(__name__)


def get_secret(secret_client: SecretClient, secret_name: str) -> str:
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
        logger.error(f'Couldn\'t get secret "{secret_name}" from the key vault.')
        raise ValueError(f'Secret "{secret_name}" not found in the key vault.')

    return secret.value
