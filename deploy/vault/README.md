# Vault setup for vctl — self-contained config & recovery

Every Vault object `vctl` depends on lives here, so the stack is recoverable from
the vctl repo alone — even if Vault state (or the vault-iac repo) is wiped.

- **`*.tf`** — a self-contained Terraform module (HCL) for the whole Vault
  surface: SSH CA, Postgres DB engine + roles, policies, AppRoles, and GitLab
  **OIDC** + userpass. `terraform apply` bootstraps or break-glass recovers it.
- **`*.hcl`** — the five Vault policy definitions, read by `policies.tf`.
- **`postgres-owner.sh`** — the one step Terraform can't do: create the stable
  Postgres owner role (`vctl_owner`) via psql. Run it once before `apply`.

> **Criterion:** deploying Vault from *this directory alone* must be enough to
> **use** vctl — login, ssh, audit, host agents. That is the bar.
>
> `vault-iac` (Terraform) runs the **production** Vault and owns org-wide concerns
> beyond vctl (e.g. the `sre`→`sre-admin` group elevation, other services). The
> vctl OIDC role here grants `vctl-user`, which is all vctl itself needs. Keep the
> two in sync when vctl's Vault needs change.
>
> One external prerequisite vctl can't create itself: the GitLab OAuth app whose
> client_id/secret seed `kv/services/vault-oidc-gitlab` (a GitLab-side object).
> With `enable_oidc=false` (or the seed absent) the module still applies and
> login works via userpass.

## What vctl depends on

| Object | Path | Purpose |
|---|---|---|
| SSH CA + sign role | `ssh/`, `ssh/sign/sre-core` | sign per-connection SSH certs (`vctl ssh`) |
| DB connection | `database/config/vctl-pg` | issue dynamic Postgres creds (verify-full TLS) |
| DB roles | `database/roles/vctl-{ro,rw,status,migrator}` | ro=reads, rw=audit writes, status=node-agent, migrator=schema |
| Policies | `vctl-{user,ssh,admin,node,collector,host}` | least privilege per caller; `ssh` = the `vctl ssh` gate, split out so it's group-granted |
| Identity groups | `identity/group` (external) → `vctl-admins` | GitLab group → policy mapping. `vctl-admins` carries `vctl-admin` + `vctl-ssh` |
| AppRoles | `vctl-{user,collector,host,node}` | non-interactive auto-auth; `node` = node-agent only (vctl-status), `host` = full stack (vctl-rw + vctl-status) |
| OIDC + role | `auth/oidc`, `auth/oidc/role/vctl` | per-person GitLab SSO (`vctl login`), base grant `vctl-user` (+ group policies) |
| userpass | `auth/userpass` | bootstrap login before the OIDC seed exists |

### RBAC (group-based)

`vctl ssh` is **not** in `vctl-user` — a plain OIDC login can read inventory but not
ssh. The ssh capability is the standalone **`vctl-ssh`** policy, granted via the
**`vctl-admins`** external identity group (GitLab group `oidc_admin_group`, default
`vctl-admins`). Members of that group get `vctl-admin` (inventory writes + CA + **RBAC
management**: edit `vctl-*` policies and group mappings) **and** `vctl-ssh`. To grant
ssh without admin, add a second external group bound to `["vctl-ssh"]` only.

> ⚠️ RBAC self-management is the highest privilege here: a `vctl-admin` can write
> `vctl-*` policies and group mappings, so it can escalate itself. Keep the
> `vctl-admins` GitLab group tightly controlled. The scope is limited to `vctl-*`
> names so org-wide objects (e.g. `sre-admin`, owned by vault-iac) stay out of reach.

## Recover / bootstrap

```bash
export VAULT_ADDR=https://vault.sre.local        # admin token in VAULT_TOKEN
PG_ADMIN_PASS=<root-pw> ./postgres-owner.sh       # 1) stable owner role (psql)
terraform init && terraform apply -var pg_admin_pass=<root-pw>   # 2) all Vault objects
vault write -f database/rotate-root/vctl-pg       # 3) rotate the root DB credential
#   no GitLab OIDC seed yet?  add -var enable_oidc=false  (userpass still works)
```

Caveats:
- ⚠️ **SSH CA** uses `generate_signing_key`. The module ignores changes to it so
  `apply` never silently rotates the key — but a *fresh* mount mints a **new**
  keypair, after which every host's `TrustedUserCAKeys` must be re-onboarded
  (`vctl trust-ca` / the Ansible trust play). Restore (terraform import) a
  backed-up CA rather than regenerating where possible.
- **OIDC** needs the seed at `kv/services/vault-oidc-gitlab`. With it present and
  `enable_oidc=true` (default), `apply` configures OIDC; otherwise userpass.
- The public SRE CA (OIDC discovery TLS) defaults to the binary's embedded copy
  (`internal/config/innogrid-sre-root-ca.crt`); override with `-var sre_ca_pem_file=`.

After recovery: `vault auth list` shows `approle/ oidc/`, `vault secrets list`
shows `ssh/ database/`, and `vctl login` + `vctl ssh <host>` work end to end.
