# Per-person login. OIDC (GitLab SSO) is the primary path; userpass is the
# bootstrap fallback usable before the GitLab OAuth app / kv seed exists.
resource "vault_auth_backend" "userpass" {
  type = "userpass"
  path = "userpass"
}

# client_id/secret seed (GitLab-side object vctl can't create). enable_oidc=false
# → count 0, so plan/apply succeed before the seed exists (userpass still works).
data "vault_kv_secret_v2" "oidc" {
  count = var.enable_oidc ? 1 : 0
  mount = "kv"
  name  = "services/vault-oidc-gitlab"
}

resource "vault_jwt_auth_backend" "oidc" {
  count                 = var.enable_oidc ? 1 : 0
  path                  = "oidc"
  type                  = "oidc"
  oidc_discovery_url    = "https://gitlab.sre.local"
  oidc_discovery_ca_pem = file("${path.module}/${var.sre_ca_pem_file}")
  oidc_client_id        = data.vault_kv_secret_v2.oidc[0].data["client_id"]
  oidc_client_secret    = data.vault_kv_secret_v2.oidc[0].data["client_secret"]
  default_role          = "vctl"
}

resource "vault_jwt_auth_backend_role" "vctl" {
  count        = var.enable_oidc ? 1 : 0
  backend      = vault_jwt_auth_backend.oidc[0].path
  role_name    = "vctl"
  role_type    = "oidc"
  user_claim   = "preferred_username" # per-person identity (GitLab username)
  oidc_scopes  = ["openid", "profile", "email"]
  groups_claim = "groups_direct"
  claim_mappings = {
    preferred_username = "username"
    email              = "email"
  }
  allowed_redirect_uris = [
    "http://localhost:8250/oidc/callback",                      # vctl CLI
    "https://vault.sre.local/ui/vault/auth/oidc/oidc/callback", # Vault UI
  ]
  # vctl-user is all vctl needs; org-wide sre→sre-admin elevation lives in vault-iac.
  token_policies = ["vctl-user"]
  token_ttl      = 3600
  token_max_ttl  = 28800
}
