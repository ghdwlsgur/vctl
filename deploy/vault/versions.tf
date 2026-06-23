terraform {
  required_version = ">= 1.5"
  required_providers {
    vault = {
      source  = "hashicorp/vault"
      version = "~> 3.25"
    }
  }
}

# VAULT_ADDR / VAULT_TOKEN come from the environment (admin token).
provider "vault" {}
