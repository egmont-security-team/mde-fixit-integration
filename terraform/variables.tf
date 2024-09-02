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

variable "fixit_api_key_prod" {
  type = string
  description = "The secret used for the 4me FixIt Production environment"
  sensitive = true
}

variable "fixit_api_key_stag" {
  type = string
  description = "The secret used for the 4me FixIt Staging environment"
  sensitive = true
}
