import azure.functions as func

from src import ddc2
from src import ddc3
from src import cve

app = func.FunctionApp()

app.register_blueprint(cve.bp)
app.register_blueprint(ddc2.bp)
app.register_blueprint(ddc3.bp)
