"""
This is the entry point for the Azure Function App.
"""

import logging
import os

import azure.functions as func
from azure.monitor.opentelemetry import configure_azure_monitor

from mde_fixit_integration.src import cve, ddc2, ddc3

if conn := os.getenv("APPLICATIONINSIGHTS_CONNECTION_STRING"):
    configure_azure_monitor(connection_string=conn)
    # This is a workaround for the issue where the opentelemetry library
    # logs unwanted and duplicate messages.
    # https://github.com/Azure/azure-functions-python-worker/issues/1342

    # Stop duplicate logs (other than critical logs)
    logging.getLogger("azure.core.pipeline.policies.http_logging_policy").setLevel(
        logging.CRITICAL
    )
    # Stop unwanted logs from the exporter
    logging.getLogger("azure.monitor.opentelemetry.exporter.export").setLevel(
        logging.WARNING
    )

app = func.FunctionApp()

app.register_blueprint(cve.bp)
app.register_blueprint(ddc2.bp)
app.register_blueprint(ddc3.bp)
