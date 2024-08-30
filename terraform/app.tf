resource "random_string" "fastate_resource_code" {
  length  = 5
  special = false
  upper   = false
}

resource "azurerm_resource_group" "app" {
  name     = "${local.repository_name}-app"
  location = local.location

  lifecycle {
    ignore_changes = [
      tags,
    ]
  }
}

resource "azurerm_storage_account" "app_state" {
  name                = "fastate${random_string.fastate_resource_code.result}"
  resource_group_name = azurerm_resource_group.app.name
  location            = azurerm_resource_group.app.location

  account_tier             = "Standard"
  account_replication_type = "LRS"

  lifecycle {
    ignore_changes = [
      tags,
    ]
  }
}

resource "azurerm_service_plan" "plan" {
  name                = "${local.repository_name}-sp"
  location            = azurerm_resource_group.app.location
  resource_group_name = azurerm_resource_group.app.name

  os_type  = "Linux"
  sku_name = "Y1"

  lifecycle {
    ignore_changes = [
      tags,
    ]
  }
}

resource "azurerm_linux_function_app" "app" {
  name                = "${local.repository_name}-fa"
  location            = azurerm_resource_group.app.location
  resource_group_name = azurerm_resource_group.app.name

  service_plan_id            = azurerm_service_plan.plan.id
  storage_account_name       = azurerm_storage_account.app_state.name
  storage_account_access_key = azurerm_storage_account.app_state.primary_access_key

  site_config {
    application_insights_connection_string = azurerm_application_insights.app_logging.instrumentation_key
  }

  identity {
    type = "UserAssigned"
    identity_ids = [
      azurerm_user_assigned_identity.app_mi.id
    ]
  }

  app_settings = {
    "AZURE_FUNCTIONS_ENVIRONMENT": "Production",
    "FUNCTIONS_WORKER_RUNTIME": "python",
    "SCM_DO_BUILD_DURING_DEPLOYMENT": 1,
    "ENABLE_ORYX_BUILD": 1,
    "KEY_VAULT_NAME" : "kv-mde-fixit-int-prod01",
    "CVE_DEVICE_THRESHOLD" : 20
  }

  lifecycle {
    ignore_changes = [
      tags,
    ]
  }
}

resource "azurerm_linux_function_app_slot" "stag" {
  name                       = "stag"
  function_app_id            = azurerm_linux_function_app.app.id
  storage_account_name       = azurerm_storage_account.app_state.name
  storage_account_access_key = azurerm_storage_account.app_state.primary_access_key

  site_config {
    application_insights_connection_string = azurerm_application_insights.app_logging.instrumentation_key
  }

  identity {
    type = "UserAssigned"
    identity_ids = [
      azurerm_user_assigned_identity.app_mi.id
    ]
  }

  app_settings = {
    "AZURE_FUNCTIONS_ENVIRONMENT": "Staging",
    "FUNCTIONS_WORKER_RUNTIME": "python",
    "SCM_DO_BUILD_DURING_DEPLOYMENT": 1,
    "ENABLE_ORYX_BUILD": 1,
    "KEY_VAULT_NAME" : "kv-mde-fixit-int-stag01",
    "CVE_DEVICE_THRESHOLD" : 5
  }

  lifecycle {
    ignore_changes = [
      tags,
    ]
  }
}

resource "azurerm_user_assigned_identity" "app_mi" {
  name                = "${local.repository_name}-app-mi"
  resource_group_name = azurerm_resource_group.app.name
  location            = azurerm_resource_group.app.location

  lifecycle {
    ignore_changes = [
      tags,
    ]
  }
}
