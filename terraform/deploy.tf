resource "azurerm_resource_group" "deployment" {
  name     = "${local.repository_name}-deployment"
  location = local.location
}

resource "azurerm_user_assigned_identity" "deployment_mi" {
  name                = "${local.repository_name}-deployment-mi"
  resource_group_name = azurerm_resource_group.deployment.name
  location            = azurerm_resource_group.deployment.location
}

resource "azurerm_role_assignment" "deployment_mi_owner" {
  scope                = data.azurerm_subscription.current.id
  role_definition_name = "Contributor"
  principal_id         = azurerm_user_assigned_identity.deployment_mi.principal_id
}

resource "azurerm_federated_identity_credential" "env_stag" {
  name                = "gh-actions-env-stag"
  resource_group_name = azurerm_resource_group.deployment.name
  parent_id           = azurerm_user_assigned_identity.deployment_mi.id
  audience            = ["api://AzureADTokenExchange"]
  issuer              = "https://token.actions.githubusercontent.com"
  subject             = "repo:egmont-security-team/${local.repository_name}:environment:${github_repository_environment.stag.environment}"
}

resource "azurerm_federated_identity_credential" "env_prod" {
  name                = "gh-actions-env-prod"
  resource_group_name = azurerm_resource_group.deployment.name
  parent_id           = azurerm_user_assigned_identity.deployment_mi.id
  audience            = ["api://AzureADTokenExchange"]
  issuer              = "https://token.actions.githubusercontent.com"
  subject             = "repo:egmont-security-team/${local.repository_name}:environment:${github_repository_environment.prod.environment}"
}
