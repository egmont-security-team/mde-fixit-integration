"""
Shared logger used by multiple files.
"""

import os

import logging

from opencensus.ext.azure.log_exporter import AzureLogHandler


def init_logger() -> logging.Logger:
    """
    Initialise the logger, setting it up with special AzureLogHandler.
    This allows for custom_properties in Azure application insights.

    returns:
        Logger: The logger instance.
    """
    logger = logging.getLogger(__name__)
    connection_string = os.environ["APPLICATIONINSIGHTS_CONNECTION_STRING"]

    if not connection_string:
        logger.error(
            'Couldn\'t setup Application Insights logging since "APPLICATIONINSIGHTS_CONNECTION_STRING" is not present.'
        )

    if not logger.handlers:
        azure_handler = AzureLogHandler(connection_string=connection_string)
        logger.addHandler(azure_handler)

    return logger


logger = init_logger()
