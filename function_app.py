import azure.functions as func
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential
from src import ddc
from src import cve

credential = DefaultAzureCredential()

KEY_VAULT_NAME = "dae1041-soc-kv001"
KEY_VAULT_URI = f"https://{KEY_VAULT_NAME}.vault.azure.net"
client = SecretClient(vault_url=KEY_VAULT_URI, credential=credential)

app = func.FunctionApp()
app.register_blueprint(ddc.bp)
app.register_blueprint(cve.bp)
