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

resource "azurerm_user_assigned_identity" "app" {
  name                = "${local.repository_name}-app-mi"
  resource_group_name = azurerm_resource_group.app.name
  location            = azurerm_resource_group.app.location

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
  sku_name = "EP1"

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

  service_plan_id             = azurerm_service_plan.plan.id
  storage_account_name        = azurerm_storage_account.app_state.name
  storage_account_access_key  = azurerm_storage_account.app_state.primary_access_key
  functions_extension_version = "~4"

  client_certificate_enabled    = true
  client_certificate_mode       = "Required"
  https_only                    = true

  site_config {
    minimum_tls_version                    = "1.2"
    application_insights_connection_string = azurerm_application_insights.app_logging.connection_string
    
    ip_restriction_default_action = "Allow"
    scm_ip_restriction_default_action = "Allow"

    application_stack {
      python_version = "3.11"
    }

    cors {
      allowed_origins = ["https://portal.azure.com"]
    }
  }

  identity {
    type = "UserAssigned"
    identity_ids = [
      azurerm_user_assigned_identity.app.id
    ]
  }

  app_settings = {
    "AZURE_CLIENT_ID" : azurerm_user_assigned_identity.app.client_id,
    "AZURE_FUNCTIONS_ENVIRONMENT" : "Production",
    "FUNCTIONS_WORKER_RUNTIME" : "python",
    "WEBSITE_RUN_FROM_PACKAGE" : 1,
    "WEBSITE_ENABLE_SYNC_UPDATE_SITE" : "true",
    "WEBSITE_CONTENTAZUREFILECONNECTIONSTRING" : azurerm_storage_account.app_state.primary_connection_string,
    "WEBSITE_CONTENTSHARE" : "mde-fixit-int-prod",
    "SCM_DO_BUILD_DURING_DEPLOYMENT" : 1,
    "ENABLE_ORYX_BUILD" : 1,
    "KEY_VAULT_NAME" : azurerm_key_vault.prod.name,
    "CVE_THRESHOLD" : 20,
    "CVE_SERVER_THRESHOLD" : 500,
  }

  lifecycle {
    ignore_changes = [
      tags,
      app_settings["SCM_DO_BUILD_DURING_DEPLOYMENT"],
      app_settings["WEBSITE_RUN_FROM_PACKAGE"],
      app_settings["CVE_THRESHOLD"],
      app_settings["CVE_SERVER_THRESHOLD"],
    ]
  }
}

resource "azurerm_linux_function_app_slot" "stag" {
  name                        = "staging"
  function_app_id             = azurerm_linux_function_app.app.id
  storage_account_name        = azurerm_storage_account.app_state.name
  storage_account_access_key  = azurerm_storage_account.app_state.primary_access_key
  functions_extension_version = "~4"

  client_certificate_enabled    = true
  client_certificate_mode       = "Required"
  https_only                    = true

  site_config {
    minimum_tls_version                    = "1.2"
    application_insights_connection_string = azurerm_application_insights.app_logging.connection_string

    ip_restriction_default_action = "Allow"
    scm_ip_restriction_default_action = "Allow"

    application_stack {
      python_version = "3.11"
    }

    cors {
      allowed_origins = ["https://portal.azure.com"]
    }
  }

  identity {
    type = "UserAssigned"
    identity_ids = [
      azurerm_user_assigned_identity.app.id
    ]
  }

  app_settings = {
    "AZURE_CLIENT_ID" : azurerm_user_assigned_identity.app.client_id,
    "AZURE_FUNCTIONS_ENVIRONMENT" : "Staging",
    "FUNCTIONS_WORKER_RUNTIME" : "python",
    "WEBSITE_RUN_FROM_PACKAGE" : 1,
    "WEBSITE_ENABLE_SYNC_UPDATE_SITE" : "true",
    "WEBSITE_CONTENTAZUREFILECONNECTIONSTRING" : azurerm_storage_account.app_state.primary_connection_string,
    "WEBSITE_CONTENTSHARE" : "mde-fixit-int-stag",
    "SCM_DO_BUILD_DURING_DEPLOYMENT" : 1,
    "ENABLE_ORYX_BUILD" : 1,
    "KEY_VAULT_NAME" : azurerm_key_vault.stag.name,
    "CVE_THRESHOLD" : 10,
    "CVE_SERVER_THRESHOLD" : 5,
  }

  lifecycle {
    ignore_changes = [
      tags,
      app_settings["SCM_DO_BUILD_DURING_DEPLOYMENT"],
      app_settings["WEBSITE_RUN_FROM_PACKAGE"],
      app_settings["CVE_THRESHOLD"],
      app_settings["CVE_SERVER_THRESHOLD"],
    ]
  }
}
