import os
import logging

from opencensus.ext.azure.log_exporter import AzureLogHandler


def init_logger():
    logger = logging.getLogger(__name__)
    instrumentation_key = os.environ["APPLICATIONINSIGHTS_CONNECTION_STRING"]

    if not instrumentation_key:
        logger.error(
            'Couldn\'t setup Application Insights logging since "APPLICATIONINSIGHTS_CONNECTION_STRING" is not present.'
        )

    if not logger.handlers:
        azure_handler = AzureLogHandler(
            connection_string=instrumentation_key
        )
        logger.addHandler(azure_handler)

    return logger


logger = init_logger()
