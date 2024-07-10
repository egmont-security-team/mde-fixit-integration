import azure.functions as func
from azure.monitor.opentelemetry import configure_azure_monitor

from src import cve, ddc2, ddc3

configure_azure_monitor()

app = func.FunctionApp()

app.register_blueprint(cve.bp)
app.register_blueprint(ddc2.bp)
app.register_blueprint(ddc3.bp)
