resource "azurerm_log_analytics_workspace" "app" {
  name                = "${local.repository_name}-law"
  location            = "West Europe"
  resource_group_name = azurerm_resource_group.app.name
  sku                 = "PerGB2018"
  retention_in_days   = 30

  lifecycle {
    ignore_changes = [
      tags,
    ]
  }
}

resource "azurerm_application_insights" "app_logging" {
  name                = "${local.repository_name}-ai"
  location            = azurerm_resource_group.app.location
  resource_group_name = azurerm_resource_group.app.name
  workspace_id        = azurerm_log_analytics_workspace.app.id
  application_type    = "web"

  lifecycle {
    ignore_changes = [
      tags,
    ]
  }
}
