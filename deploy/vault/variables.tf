variable "pg_host" {
  type        = string
  default     = "vctl-postgres.vctl.svc.cluster.local"
  description = "Postgres host Vault connects to (in-cluster service DNS)"
}

variable "pg_port" {
  type    = number
  default = 5432
}

variable "pg_db" {
  type    = string
  default = "vctl"
}

variable "pg_admin_user" {
  type        = string
  default     = "vctl_admin"
  description = "Postgres user Vault uses to create dynamic roles"
}

variable "pg_admin_pass" {
  type        = string
  sensitive   = true
  description = "Postgres admin password (-var or TF_VAR_pg_admin_pass; rotate with database/rotate-root/vctl-pg after apply)"
}

variable "pg_sslmode" {
  type    = string
  default = "verify-full"
}

variable "pg_migration_owner" {
  type        = string
  default     = "vctl_owner"
  description = "Stable Postgres role owning migration objects (created by postgres-owner.sh, not Terraform)"
}

variable "enable_oidc" {
  type        = bool
  default     = true
  description = "Configure GitLab OIDC login (needs the kv seed below). false = userpass only."
}

variable "sre_ca_pem_file" {
  type        = string
  default     = "../../internal/config/innogrid-sre-root-ca.crt"
  description = "Public SRE root CA for OIDC discovery TLS (the binary's embedded copy by default)"
}
