resource "azurerm_application_insights" "app_logging" {
  name                = "${local.repository_name}-ai"
  location            = azurerm_resource_group.app.location
  resource_group_name = azurerm_resource_group.app.name
  application_type    = "web"

  lifecycle {
    ignore_changes = [
      tags,
    ]
  }
}
