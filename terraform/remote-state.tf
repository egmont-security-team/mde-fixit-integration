resource "random_string" "tfstate_resource_code" {
  length  = 5
  special = false
  upper   = false
}

resource "azurerm_resource_group" "tfstate" {
  name     = "${local.repository_name}-tfstate"
  location = local.location

  tags = {
    "service_level"        = "24-7"
    "sub_cost_center_code" = "DAE-1041-03"
  }
}

resource "azurerm_storage_account" "tfstate" {
  name                            = "tfstate${random_string.tfstate_resource_code.result}"
  resource_group_name             = azurerm_resource_group.tfstate.name
  location                        = azurerm_resource_group.tfstate.location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  allow_nested_items_to_be_public = false

  tags = {
    "service_level" = "24-7"
  }
}

resource "azurerm_storage_container" "tfstate_deploy" {
  name                  = "tfstate-deploy"
  storage_account_name  = azurerm_storage_account.tfstate.name
  container_access_type = "private"
}

resource "azurerm_storage_container" "tfstate_stag" {
  name                  = "tfstate-stag"
  storage_account_name  = azurerm_storage_account.tfstate.name
  container_access_type = "private"
}

resource "azurerm_storage_container" "tfstate_prod" {
  name                  = "tfstate-prod"
  storage_account_name  = azurerm_storage_account.tfstate.name
  container_access_type = "private"
}
