"""
Shared logger used by multiple files.
"""

from logging import DEBUG, getLogger

from azure.monitor.opentelemetry import configure_azure_monitor

configure_azure_monitor()

logger = getLogger(__name__)
logger.setLevel(DEBUG)
