import azure.functions as func
# from src import ddc
from src import cve

app = func.FunctionApp()

# app.register_blueprint(ddc.bp)
app.register_blueprint(cve.bp)
