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
    storage_account_name = "tfstate2q6qx"
    container_name       = "tfstate-deploy"
    key                  = "terraform.tfstate"
  }

  required_version = ">= 1.9.2"
}

provider "azurerm" {
  features {}
}

provider "github" {
  owner = "egmont-security-team"
}

locals {
  location            = "West Europe"
  repository_name     = "mde-fixit-integration"
}
