data "azurerm_client_config" "current" {}

resource "azurerm_key_vault" "prod" {
  name                = "${local.repository_name_short}-kv-prod"
  location            = azurerm_resource_group.app.location
  resource_group_name = azurerm_resource_group.app.name
  tenant_id           = data.azurerm_client_config.current.tenant_id

  enabled_for_disk_encryption = true
  purge_protection_enabled    = false
  soft_delete_retention_days  = 7

  sku_name = "standard"

  access_policy {
    tenant_id = data.azurerm_client_config.current.tenant_id
    object_id = data.azurerm_client_config.current.object_id

    secret_permissions = [
      "Backup",
      "Delete",
      "Get",
      "List",
      "Purge",
      "Recover",
      "Restore",
      "Set",
    ]
  }

  access_policy {
    tenant_id = azurerm_user_assigned_identity.app.tenant_id
    object_id = azurerm_user_assigned_identity.app.principal_id

    secret_permissions = [
      "Get",
    ]
  }

  lifecycle {
    ignore_changes = [
      tags,
    ]
  }
}

resource "azurerm_key_vault" "stag" {
  name                = "${local.repository_name_short}-kv-stag"
  location            = azurerm_resource_group.app.location
  resource_group_name = azurerm_resource_group.app.name
  tenant_id           = data.azurerm_client_config.current.tenant_id

  enabled_for_disk_encryption = true
  purge_protection_enabled    = false
  soft_delete_retention_days  = 7

  sku_name = "standard"

  access_policy {
    tenant_id = data.azurerm_client_config.current.tenant_id
    object_id = data.azurerm_client_config.current.object_id

    secret_permissions = [
      "Backup",
      "Delete",
      "Get",
      "List",
      "Purge",
      "Recover",
      "Restore",
      "Set",
    ]
  }

  access_policy {
    tenant_id = azurerm_user_assigned_identity.app.tenant_id
    object_id = azurerm_user_assigned_identity.app.principal_id

    secret_permissions = [
      "Get",
    ]
  }

  lifecycle {
    ignore_changes = [
      tags,
    ]
  }
}

# PRODUCTION: Key Vault Secrets

resource "azurerm_key_vault_secret" "azure_mde_tenant_prod" {
  name         = "Azure-MDE-Tenant"
  value        = "d5dfa732-4450-4094-a0f9-50bd719272da"
  key_vault_id = azurerm_key_vault.prod.id
}

resource "azurerm_key_vault_secret" "azure_mde_client_id_prod" {
  name         = "Azure-MDE-Client-ID"
  value        = "f160a34b-0ca1-419a-af7a-d5e70a114c7b"
  key_vault_id = azurerm_key_vault.prod.id
}

resource "azurerm_key_vault_secret" "azure_mde_secret_value_prod" {
  name         = "Azure-MDE-Secret-Value"
  value        = var.azure_mde_secret_prod
  key_vault_id = azurerm_key_vault.prod.id
}

resource "azurerm_key_vault_secret" "fixit_4me_base_url_prod" {
  name         = "FixIt-4Me-Base-URL"
  value        = "https://api.4me.com/v1"
  key_vault_id = azurerm_key_vault.prod.id
}

resource "azurerm_key_vault_secret" "fixit_4me_account_prod" {
  name         = "FixIt-4Me-Account"
  value        = "egmont-it"
  key_vault_id = azurerm_key_vault.prod.id
}

resource "azurerm_key_vault_secret" "fixit_4me_api_key_prod" {
  name         = "FixIt-4Me-API-Key"
  value        = var.fixit_api_key_prod
  key_vault_id = azurerm_key_vault.prod.id
}

resource "azurerm_key_vault_secret" "cve_single_fixit_template_id_prod" {
  name         = "CVE-Single-FixIt-Template-ID"
  value        = "187104"
  key_vault_id = azurerm_key_vault.prod.id
}

resource "azurerm_key_vault_secret" "cve_multi_fixit_template_id_prod" {
  name         = "CVE-Multi-FixIt-Template-ID"
  value        = "187105"
  key_vault_id = azurerm_key_vault.prod.id
}

resource "azurerm_key_vault_secret" "cve_service_instance_id_prod" {
  name         = "CVE-Service-Instance-ID"
  value        = "217021"
  key_vault_id = azurerm_key_vault.prod.id
}

resource "azurerm_key_vault_secret" "cve_sd_team_id_prod" {
  name         = "CVE-SD-Team-ID"
  value        = "8827"
  key_vault_id = azurerm_key_vault.prod.id
}

resource "azurerm_key_vault_secret" "cve_mw_team_id_prod" {
  name         = "CVE-MW-Team-ID"
  value        = "14819"
  key_vault_id = azurerm_key_vault.prod.id
}

resource "azurerm_key_vault_secret" "cve_sec_team_id_prod" {
  name         = "CVE-SEC-Team-ID"
  value        = "10659"
  key_vault_id = azurerm_key_vault.prod.id
}

resource "azurerm_key_vault_secret" "cve_cad_team_id_prod" {
  name         = "CVE-CAD-Team-ID"
  value        = "23148"
  key_vault_id = azurerm_key_vault.prod.id
}

# STAGING: Key Vault Secrets

resource "azurerm_key_vault_secret" "azure_mde_tenant_stag" {
  name         = "Azure-MDE-Tenant"
  value        = "a0078ebe-2612-4db5-b753-0c84c38e4674"
  key_vault_id = azurerm_key_vault.stag.id
}

resource "azurerm_key_vault_secret" "azure_mde_client_id_stag" {
  name         = "Azure-MDE-Client-ID"
  value        = "9029e87b-dc80-4eef-83ad-ef91cefac944"
  key_vault_id = azurerm_key_vault.stag.id
}

resource "azurerm_key_vault_secret" "azure_mde_secret_value_stag" {
  name         = "Azure-MDE-Secret-Value"
  value        = var.azure_mde_secret_stag
  key_vault_id = azurerm_key_vault.stag.id
}

resource "azurerm_key_vault_secret" "fixit_4me_base_url_stag" {
  name         = "FixIt-4Me-Base-URL"
  value        = "https://api.4me.qa/v1"
  key_vault_id = azurerm_key_vault.stag.id
}

resource "azurerm_key_vault_secret" "fixit_4me_account_stag" {
  name         = "FixIt-4Me-Account"
  value        = "egmont-it-new"
  key_vault_id = azurerm_key_vault.stag.id
}

resource "azurerm_key_vault_secret" "fixit_4me_api_key_stag" {
  name         = "FixIt-4Me-API-Key"
  value        = var.fixit_api_key_stag
  key_vault_id = azurerm_key_vault.stag.id
}

resource "azurerm_key_vault_secret" "cve_single_fixit_template_id_stag" {
  name         = "CVE-Single-FixIt-Template-ID"
  value        = "186253"
  key_vault_id = azurerm_key_vault.stag.id
}

resource "azurerm_key_vault_secret" "cve_multi_fixit_template_id_stag" {
  name         = "CVE-Multi-FixIt-Template-ID"
  value        = "187490"
  key_vault_id = azurerm_key_vault.stag.id
}

resource "azurerm_key_vault_secret" "cve_service_instance_id_stag" {
  name         = "CVE-Service-Instance-ID"
  value        = "70782"
  key_vault_id = azurerm_key_vault.stag.id
}

resource "azurerm_key_vault_secret" "cve_sd_team_id_stag" {
  name         = "CVE-SD-Team-ID"
  value        = "12104"
  key_vault_id = azurerm_key_vault.stag.id
}

resource "azurerm_key_vault_secret" "cve_mw_team_id_stag" {
  name         = "CVE-MW-Team-ID"
  value        = "17997"
  key_vault_id = azurerm_key_vault.stag.id
}

resource "azurerm_key_vault_secret" "cve_sec_team_id_stag" {
  name         = "CVE-SEC-Team-ID"
  value        = "24088"
  key_vault_id = azurerm_key_vault.stag.id
}

resource "azurerm_key_vault_secret" "cve_cad_team_id_stag" {
  name         = "CVE-CAD-Team-ID"
  value        = "26703"
  key_vault_id = azurerm_key_vault.stag.id
}
