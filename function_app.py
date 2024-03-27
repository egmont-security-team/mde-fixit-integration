import logging
from opencensus.ext.azure.log_exporter import AzureLogHandler
import azure.functions as func
from src import ddc
from src import cve

app = func.FunctionApp()

logger = logging.getLogger(__name__)
logger.addHandler(AzureLogHandler())

app.register_blueprint(ddc.bp)
app.register_blueprint(cve.bp)
