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

    try:
        connection_string = os.environ["APPLICATIONINSIGHTS_CONNECTION_STRING"]
    except KeyError:
        connection_string = ""

    if not connection_string:
        logger.warning(
            'Couldn\'t setup proper Application Insights logging since "APPLICATIONINSIGHTS_CONNECTION_STRING" is not present.'
        )
        return logger

    if not logger.handlers:
        azure_handler = AzureLogHandler(connection_string=connection_string)
        logger.addHandler(azure_handler)

    return logger


logger = init_logger()
