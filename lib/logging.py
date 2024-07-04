"""
Shared logger used by multiple files.
"""

import logging
import os

from opencensus.ext.azure.log_exporter import AzureLogHandler


def init_logger() -> logging.Logger:
    """
    Initialise the logger, setting it up with special AzureLogHandler.
    This allows for custom_properties in Azure application insights.

    returns:
        Logger: The logger instance.
    """

    current_logger = logging.getLogger(__name__)

    try:
        connection_string = os.environ["APPLICATIONINSIGHTS_CONNECTION_STRING"]
    except KeyError:
        connection_string = ""

    if not connection_string:
        current_logger.warning(
            'Couldn\'t setup proper Application Insights logging since "APPLICATIONINSIGHTS_CONNECTION_STRING" is not present.'
        )
        return current_logger

    if not current_logger.handlers:
        azure_handler = AzureLogHandler(connection_string=connection_string)
        current_logger.addHandler(azure_handler)

    return current_logger


logger = init_logger()
