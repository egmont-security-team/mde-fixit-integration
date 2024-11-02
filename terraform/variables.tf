variable "azure_mde_secret_prod" {
  type = string
  description = "The secret used for the Azure MDE Production environment"
  sensitive = true
}

variable "azure_mde_secret_stag" {
  type = string
  description = "The secret used for the Azure MDE Staging environment"
  sensitive = true
}

variable "xurrent_api_key_prod" {
  type = string
  description = "The secret used for the Xurrent production environment"
  sensitive = true
}

variable "xurrent_api_key_stag" {
  type = string
  description = "The secret used for the Xurrent staging environment"
  sensitive = true
}
