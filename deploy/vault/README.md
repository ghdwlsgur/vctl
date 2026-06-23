# Vault setup for vctl — self-contained config & recovery

Every Vault object `vctl` depends on lives here, so the stack is recoverable from
the vctl repo alone — even if Vault state (or the vault-iac repo) is wiped.

- **`setup.sh`** — one idempotent script that creates the **whole** surface:
  Postgres DB engine + roles, all policies, the SSH CA, the AppRoles, and the
  GitLab **OIDC** auth. Run it to bootstrap or to break-glass recover.
- **`*.hcl`** — the five policy definitions (`vctl-user/admin/node/collector/host`).

> **Criterion:** deploying Vault from *this directory alone* (`./setup.sh`) must
> be enough to **use** vctl — login, ssh, audit, host agents. That is the bar.
>
> `vault-iac` (Terraform) runs the **production** Vault and owns org-wide concerns
> beyond vctl (e.g. the `sre`→`sre-admin` group elevation, other services). The
> vctl OIDC role here grants `vctl-user`, which is all vctl itself needs. Keep the
> two in sync when vctl's Vault needs change.
>
> One external prerequisite vctl can't create itself: the GitLab OAuth app whose
> client_id/secret seed `kv/services/vault-oidc-gitlab` (a GitLab-side object).
> `setup.sh` configures OIDC when that seed exists, else uses userpass.

## What vctl depends on

| Object | Path | Purpose |
|---|---|---|
| SSH CA + sign role | `ssh/`, `ssh/sign/sre-core` | sign per-connection SSH certs (`vctl ssh`) |
| DB connection | `database/config/vctl-pg` | issue dynamic Postgres creds (verify-full TLS) |
| DB roles | `database/roles/vctl-{ro,rw,status,migrator}` | ro=reads, rw=audit writes, status=node-agent, migrator=schema |
| Policies | `vctl-{user,admin,node,collector,host}` | least privilege per caller |
| AppRoles | `vctl-{user,collector,host}` | non-interactive auto-auth (services/hosts) |
| OIDC + role | `auth/oidc`, `auth/oidc/role/vctl` | per-person GitLab SSO (`vctl login`), grants `vctl-user` |
| userpass | `auth/userpass` | bootstrap login before the OIDC seed exists |

## Recover

```bash
export VAULT_ADDR=https://vault.sre.local        # token with admin rights
PG_ADMIN_PASS=<root-pw> ./setup.sh               # recreates everything, idempotent
```

Caveats:
- ⚠️ **SSH CA** uses `generate_signing_key`. `setup.sh` leaves an existing CA key
  intact, but a *fresh* mount mints a **new** keypair — then every host's
  `TrustedUserCAKeys` must be re-onboarded (`vctl trust-ca` / the Ansible trust
  play). Restore the backed-up CA key rather than regenerating where possible.
- **OIDC** needs the client_id/secret seed at `kv/services/vault-oidc-gitlab`
  (from the gitlab-structure IaC, or seeded by hand). `setup.sh` skips OIDC with
  a notice if the seed is absent — seed it, then re-run.
- The public SRE CA (OIDC discovery TLS) is read from the binary's embedded copy
  (`internal/config/innogrid-sre-root-ca.crt`); override with `SRE_CA=/path`.

After recovery: `vault auth list` shows `approle/ oidc/`, `vault secrets list`
shows `ssh/ database/`, and `vctl login` + `vctl ssh <host>` work end to end.
