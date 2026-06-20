# OIDC SSO Phase 2

Goal: let users run `vctl login`, complete browser SSO, and receive Vault policies through group mapping without per-user Vault account creation.

This guide assumes GitLab at `gitlab.sre.local` is the identity provider.

```bash
# 1. Register an OIDC application in GitLab.
#    Redirect URI:  http://localhost:8250/oidc/callback
#    Scopes:        openid, profile, email
#    Save client_id and client_secret.

# 2. Enable Vault OIDC auth.
vault auth enable oidc

vault write auth/oidc/config \
  oidc_discovery_url="https://gitlab.sre.local" \
  oidc_client_id="<client_id>" \
  oidc_client_secret="<client_secret>" \
  default_role="vctl"

# 3. Configure the role and map group claims to policies.
vault write auth/oidc/role/vctl \
  user_claim="sub" \
  allowed_redirect_uris="http://localhost:8250/oidc/callback" \
  bound_audiences="<client_id>" \
  oidc_scopes="openid,profile,email,groups" \
  groups_claim="groups" \
  policies="vctl-user"

# 4. Optional: map GitLab groups to Vault external groups.
#    sre-team -> vctl-user
#    sre-admins -> vctl-admin
```

After the Vault side is ready, switch the client default:

```yaml
# .vctl/config.yaml or compiled defaults in internal/config/config.go
auth_method: oidc
```

The client code already implements this flow through `vctl login --method oidc`.
