import azure.functions as func
from src.ddc_automation import bp as ddc_bp
from src.cve_automation import bp as cve_bp

app = func.FunctionApp()

app.register_blueprint(ddc_bp)
app.register_blueprint(cve_bp)
