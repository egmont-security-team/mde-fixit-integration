import logging

import azure.functions as func
from azure.monitor.opentelemetry import configure_azure_monitor

from src import cve, ddc2, ddc3

configure_azure_monitor()
# This is a workaround for the issue where the optentelemetry
# integration logs unwanted messages to the console.
# https://github.com/Azure/azure-functions-python-worker/issues/1342
logging.getLogger("azure.core.pipeline.policies.http_logging_policy").setLevel(
    logging.WARNING
)
logging.getLogger("azure.monitor.opentelemetry.exporter.export").setLevel(
    logging.WARNING
)

app = func.FunctionApp()

app.register_blueprint(cve.bp)
app.register_blueprint(ddc2.bp)
app.register_blueprint(ddc3.bp)
