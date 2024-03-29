import logging
import os
from opencensus.ext.azure.log_exporter import AzureLogHandler


def init_logger():
    logger = logging.getLogger(__name__)
    instrumentation_key = os.getenv("APPINSIGHTS_INSTRUMENTATIONKEY")

    if not logger.handlers:
        azure_handler = AzureLogHandler(
            connection_string=f"InstrumentationKey={instrumentation_key}"
        )
        logger.addHandler(azure_handler)

    return logger


logger = init_logger()
