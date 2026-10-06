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

variable "oidc_admin_group" {
  type        = string
  default     = "vctl-admins"
  description = "GitLab group mapped to vctl-admin, vctl-ssh, and vctl-auditor."
}

variable "oidc_ssh_group" {
  type        = string
  default     = "vctl-ssh-users"
  description = "GitLab group mapped to the server-enforced vctl-ssh signing policy."
}

variable "oidc_auditor_group" {
  type        = string
  default     = "vctl-auditors"
  description = "GitLab group mapped to read-only access and session audit data."
}

variable "sre_ca_pem_file" {
  type        = string
  default     = "../../internal/config/innogrid-sre-root-ca.crt"
  description = "Public SRE root CA for OIDC discovery TLS (the binary's embedded copy by default)"
}

variable "node_access_hosts" {
  type = set(string)
  default = [
    "sre-srv-0025", "sre-srv-0026", "sre-srv-0030", "sre-srv-0031", "sre-srv-0032",
    "sre-srv-0034", "sre-srv-0035", "sre-srv-0036", "sre-srv-0038", "sre-srv-0041",
    "sre-srv-0042", "sre-srv-0047", "sre-srv-0048", "sre-srv-0050", "sre-srv-0051",
    "sre-srv-0054", "sre-srv-0055", "sre-srv-0058", "sre-srv-0059", "sre-srv-0093",
    "sre-srv-0094", "sre-srv-0100", "sre-srv-0101", "sre-srv-0102", "sre-srv-0103",
    "sre-srv-0104"
  ]
  description = "Inventory hostnames allowed to enroll as node-access mTLS agents. Each gets an isolated PKI role and AppRole."
}
