resource "github_repository" "repo" {
  name          = local.repository_name
  visibility    = "public"
  has_downloads = true
  has_issues    = true
}

resource "github_repository_environment" "prod" {
  environment         = "prod"
  repository          = github_repository.repo.name
  prevent_self_review = true

  deployment_branch_policy {
    protected_branches     = true
    custom_branch_policies = false
  }
}

resource "github_repository_environment" "stag" {
  environment         = "stag"
  repository          = github_repository.repo.name
  prevent_self_review = true

  deployment_branch_policy {
    protected_branches     = true
    custom_branch_policies = false
  }
}

resource "github_actions_secret" "azure_client_id" {
  repository      = github_repository.repo.name
  secret_name     = "AZURE_CLIENT_ID"
  plaintext_value = azurerm_user_assigned_identity.deployment_mi.client_id
}

resource "github_actions_secret" "azure_subscription_id" {
  repository      = github_repository.repo.name
  secret_name     = "AZURE_SUBSCRIPTION_ID"
  plaintext_value = data.azurerm_subscription.current.subscription_id
}

resource "github_actions_secret" "azure_tenant_id" {
  repository      = github_repository.repo.name
  secret_name     = "AZURE_TENANT_ID"
  plaintext_value = data.azurerm_subscription.current.tenant_id
}
