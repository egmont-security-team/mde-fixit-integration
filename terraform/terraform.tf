terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.115"
    }
    github = {
      source  = "integrations/github"
      version = "~> 6.0"
    }
  }

  backend "azurerm" {
    resource_group_name  = "mde-fixit-integration-tfstate"
    storage_account_name = "tfstate2x8aa"
    container_name       = "tfstate"
    key                  = "terraform.tfstate"
  }

  required_version = ">= 1.9.2"
}

provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy    = true
      recover_soft_deleted_key_vaults = true
    }
  }
}

provider "github" {
  owner = "egmont-security-team"
}

locals {
  location            = "West Europe"
  github_organization = "egmont-security-team"
  repository_name     = "mde-fixit-integration"
}
