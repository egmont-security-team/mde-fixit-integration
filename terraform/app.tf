resource "random_string" "state-resource-code" {
  length  = 5
  special = false
  upper   = false
}

resource "azurerm_resource_group" "app" {
  name     = "${local.repository_name}-app"
  location = local.location
}

resource "azurerm_storage_account" "function-app-state" {
  name                     = "functionappstate${random_string.resource_code.result}"
  resource_group_name      = azurerm_resource_group.app.name
  location                 = azurerm_resource_group.app.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
}

resource "azurerm_app_service_plan" "function-app-service-plan" {
  name                = "${local.repository_name}-appserviceplan"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  sku {
    tier = "Standard"
    size = "S1"
  }
}

resource "azurerm_function_app" "app" {
  name                       = "${local.repository_name}-functionapp"
  location                   = azurerm_resource_group.app.location
  resource_group_name        = azurerm_resource_group.app.name
  app_service_plan_id        = azurerm_app_service_plan.function-app-service-plan.id
  storage_account_name       = azurerm_storage_account.function-app-state.name
  storage_account_access_key = azurerm_storage_account.function-app-state.primary_access_key

  identity {
    type = "UserAssigned"
    identity_ids = [
      azurerm_user_assigned_identity.app-mi.id
    ]
  }

  app_settings = {
    "APPLICATIONINSIGHTS_CONNECTION_STRING" : "TODO",
    "KEY_VAULT_NAME" : "kv-mde-fixit-int-prod01",
    "CVE_DEVICE_THRESHOLD" : 20
  }
}

resource "azurerm_function_app_slot" "stag-slot" {
  name                       = "stag"
  location                   = azurerm_resource_group.app.location
  resource_group_name        = azurerm_resource_group.app.name
  app_service_plan_id        = azurerm_app_service_plan.function-app-service-plan.id
  function_app_name          = azurerm_function_app.app.name
  storage_account_name       = azurerm_storage_account.function-app-state.name
  storage_account_access_key = azurerm_storage_account.function-app-state.primary_access_key

  identity {
    type = "UserAssigned"
    identity_ids = [
      azurerm_user_assigned_identity.app-mi.id
    ]
  }

  app_settings = {
    "APPLICATIONINSIGHTS_CONNECTION_STRING" : "TODO",
    "KEY_VAULT_NAME" : "kv-mde-fixit-int-stag01",
    "CVE_DEVICE_THRESHOLD" : 5
  }
}

resource "azurerm_user_assigned_identity" "app-mi" {
  name                = "${local.repository_name}-app-mi"
  resource_group_name = azurerm_resource_group.app.name
  location            = azurerm_resource_group.app.location
}
