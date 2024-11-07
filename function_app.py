"""Entry point for the Azure Function App."""

import logging
import os

import azure.functions as func
from azure.monitor.opentelemetry import configure_azure_monitor

from mde_fixit_integration.src import cve, ddc2, ddc3

if conn := os.getenv("APPLICATIONINSIGHTS_CONNECTION_STRING"):
    # This is a workaround for the issue where the opentelemetry library
    # logs unwanted and duplicate messages.
    # https://github.com/Azure/azure-sdk-for-python/tree/main/sdk/monitor/azure-monitor-opentelemetry#logging-issues

    # Stop duplicate logs
    logging.getLogger("azure.core.pipeline.policies.http_logging_policy").setLevel(logging.CRITICAL)
    # Stop unwated logs
    logging.getLogger("azure.monitor.opentelemetry.exporter.export").setLevel(logging.WARNING)

    configure_azure_monitor(connection_string=conn)

app = func.FunctionApp()

app.register_blueprint(cve.bp)
app.register_blueprint(ddc2.bp)
app.register_blueprint(ddc3.bp)
