"""
This is the entry point for the Azure Function App.
"""

import logging
import os

import azure.functions as func
from azure.monitor.opentelemetry import configure_azure_monitor

from mde_fixit_integration.src import cve, ddc2, ddc3

if conn := os.getenv("APPLICATIONINSIGHTS_CONNECTION_STRING"):
    # This is a workaround for the issue where the root logger creates duplicate and unwanted logs.
    # This should be removed when the issue is fixed in the future.
    # https://github.com/Azure/azure-sdk-for-python/tree/main/sdk/monitor/azure-monitor-opentelemetry#logging-issues
    root_logger = logging.getLogger()
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    configure_azure_monitor(connection_string=conn)

app = func.FunctionApp()

app.register_blueprint(cve.bp)
app.register_blueprint(ddc2.bp)
app.register_blueprint(ddc3.bp)
