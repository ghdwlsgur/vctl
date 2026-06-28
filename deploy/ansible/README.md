# Fleet onboarding (Ansible)

Playbooks that roll the vctl host stack onto existing servers. They install the
*same* units and scripts that live in `../audit` and `../node` (single source of
truth — no duplicated copies here) plus the SSH CA trust.

| Playbook | What it does |
|---|---|
| `trust-vault-ssh-ca.yml` | Install the Vault SSH CA public key as `TrustedUserCAKeys` so `vctl ssh` works (same as `vctl trust-ca`, in bulk). |
| `site.yml` | Install the full host stack: collector + watch-sessions (kernel/session audit) **and** node-agent (runtime status), with one `vctl-host` AppRole credential, Tetragon (bare VMs), DNS, and log caps. |

## Prerequisites

- The AppRole the host uses exists in Vault (see the `vault-iac` repo). Which one
  depends on `vctl_host_audit_stack`:
  - `vctl_host_audit_stack=true` (default) -> **`vctl-host`** (`vctl-audit-ingest` + `vctl-status`):
    full stack (collector + watch-sessions + node-agent).
  - `vctl_host_audit_stack=false` → **`vctl-node`** (`vctl-status` only): node-agent ONLY,
    no DB write — least privilege for liveness-only hosts.
  The playbook reads the role's `role_id` and mints a per-host `secret_id` from the
  **control node's** `VAULT_ADDR`/`VAULT_TOKEN`, so run with a token allowed to do
  `vault read auth/approle/role/<role>/role-id` and
  `vault write -f auth/approle/role/<role>/secret-id` (role = vctl-host or vctl-node).
- The release **linux binary** placed at `files/vctl` (gitignored):
  `gh release download vX.Y.Z -p 'vctl_*_linux_amd64.tar.gz' && tar -xzf … -C files/`
  (or switch the play to install the `.deb`/`.rpm` from the release).
- Hosts already trust the SSH CA (`trust-vault-ssh-ca.yml` or `vctl trust-ca`).

## Run (canary first, then waves)

```bash
# one canary host
ansible-playbook -i inventory.ini site.yml -l <canary>

# a wave / group
ansible-playbook -i inventory.ini site.yml -l seoul_wave1

# non-seoul networks: point hosts at the right LB for *.sre.local
ansible-playbook -i inventory.ini site.yml -l incheon_onprem -e vctl_host_sre_lb_ip=<lb-ip>

# k8s nodes: skip the bare-VM Tetragon install (use a DaemonSet instead)
ansible-playbook -i inventory.ini site.yml -l k8s_nodes -e vctl_host_install_tetragon=false

# rollback
ansible-playbook -i inventory.ini site.yml -l <host> -e vctl_host_state=absent
```

`vctl_host_enable_services` stays effectively gated on the `secret_id` being present, so a
host never crash-loops before its credential is in place. node-agent and
watch-sessions do **not** need Tetragon; only the collector does.

SSH host-key checking is enabled. Populate the control user's `known_hosts`
through a trusted channel before onboarding a server. Re-run the play at least
every 21 days so the 30-day AppRole secret ID rotates before expiry.

> Keep real inventories and `files/` (binary, secret_id, CA pubkey) out of git —
> see `.gitignore`. Only `inventory.example.ini` is committed.

## Security notes

- **`/etc/hosts` pinning is not the security boundary.** The play points
  `vault.sre.local` / `vctl-postgres.sre.local` at `vctl_host_sre_lb_ip` for resolution
  only. Confidentiality/authenticity come from **verify-full TLS with the
  embedded private CA** — a wrong or spoofed IP fails the handshake, so no
  secret leaks. Override `vctl_host_sre_lb_ip` freely per network without weakening trust.
- **Tetragon tarball is digest-pinned.** Set `vctl_host_tetragon_sha256` per release; once
  a mirror (harbor) fronts the download URL the checksum makes a swapped tarball
  fail closed. The tarball is staged root-only under `/opt/vctl/tetragon-stage`.
- **Session marker dir stays `root:root 0700`.** Never loosen it — group/world
  write lets a non-root user forge or delete another session's marker and break
  audit attribution. The current marker backend supports root SSH sessions only;
  non-root support requires a separate authenticated privileged transport.
