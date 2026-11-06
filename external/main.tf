terraform {
  required_version = "= 1.13.1"

  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "= 5.28.0"
    }
  }

  # The wrapper supplies the state path with -backend-config=path=...; the state never sits in the checkout.
  backend "local" {}

  encryption {
    key_provider "pbkdf2" "fleet" {
      passphrase = var.state_passphrase
    }

    method "aes_gcm" "fleet" {
      keys = key_provider.pbkdf2.fleet
    }

    state {
      method   = method.aes_gcm.fleet
      enforced = true
    }

    plan {
      method   = method.aes_gcm.fleet
      enforced = true
    }
  }
}

# Passed only as TF_VAR_state_passphrase in the child process's environment.
variable "state_passphrase" {
  type      = string
  sensitive = true
}

# `hal apply` and the tests set this; the other runs leave it at the real catalog.
variable "catalog_file" {
  type    = string
  default = null
}

# hal's own tunnel: the wrapper reads its id from the machine's tunnel config, so a second tunnel in
# the account is never looked up.
variable "tunnel_id" {
  type = string
}

locals {
  fleet = yamldecode(file(coalesce(var.catalog_file, "${path.module}/../fleet.yaml")))
}
