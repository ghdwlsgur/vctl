# Fleet onboarding (Ansible)

Playbooks that roll the vctl host stack onto existing servers. They install the
*same* units and scripts that live in `../audit` and `../node` (single source of
truth — no duplicated copies here) plus the SSH CA trust.

| Playbook | What it does |
|---|---|
| `trust-vault-ssh-ca.yml` | Install the Vault SSH CA public key as `TrustedUserCAKeys` so `vctl ssh` works (same as `vctl trust-ca`, in bulk). |
| `audit-onboard.yml` | Install the full host stack: collector + watch-sessions (kernel/session audit) **and** node-agent (runtime status), with one `vctl-host` AppRole credential, Tetragon (bare VMs), DNS, and log caps. |

## Prerequisites

- The **`vctl-host` AppRole** exists in Vault (combined `vctl-rw` + `vctl-status`
  policy — see the `vault-iac` repo). The playbook reads its `role_id` and mints a
  per-host `secret_id` from the **control node's** `VAULT_ADDR`/`VAULT_TOKEN`, so
  run with a token allowed to do:
  `vault read auth/approle/role/vctl-host/role-id` and
  `vault write -f auth/approle/role/vctl-host/secret-id`.
- The release **linux binary** placed at `files/vctl` (gitignored):
  `gh release download vX.Y.Z -p 'vctl_*_linux_amd64.tar.gz' && tar -xzf … -C files/`
  (or switch the play to install the `.deb`/`.rpm` from the release).
- Hosts already trust the SSH CA (`trust-vault-ssh-ca.yml` or `vctl trust-ca`).

## Run (canary first, then waves)

```bash
# one canary host
ansible-playbook -i inventory.ini audit-onboard.yml -l <canary>

# a wave / group
ansible-playbook -i inventory.ini audit-onboard.yml -l seoul_wave1

# non-seoul networks: point hosts at the right LB for *.sre.local
ansible-playbook -i inventory.ini audit-onboard.yml -l incheon_onprem -e sre_lb_ip=<lb-ip>

# k8s nodes: skip the bare-VM Tetragon install (use a DaemonSet instead)
ansible-playbook -i inventory.ini audit-onboard.yml -l k8s_nodes -e install_tetragon=false

# rollback
ansible-playbook -i inventory.ini audit-onboard.yml -l <host> -e state=absent
```

`enable_services` stays effectively gated on the `secret_id` being present, so a
host never crash-loops before its credential is in place. node-agent and
watch-sessions do **not** need Tetragon; only the collector does.

> Keep real inventories and `files/` (binary, secret_id, CA pubkey) out of git —
> see `.gitignore`. Only `inventory.example.ini` is committed.

## Security notes

- **`/etc/hosts` pinning is not the security boundary.** The play points
  `vault.sre.local` / `vctl-postgres.sre.local` at `sre_lb_ip` for resolution
  only. Confidentiality/authenticity come from **verify-full TLS with the
  embedded private CA** — a wrong or spoofed IP fails the handshake, so no
  secret leaks. Override `sre_lb_ip` freely per network without weakening trust.
- **Tetragon tarball is digest-pinned.** Set `tetragon_sha256` per release; once
  a mirror (harbor) fronts the download URL the checksum makes a swapped tarball
  fail closed. The tarball is staged root-only under `/opt/vctl/tetragon-stage`.
- **Session marker dir stays `root:root 0700`.** Never loosen it — group/world
  write lets a non-root user forge or delete another session's marker and break
  audit attribution. Non-root-login hosts use the watch-sessions journal-tail
  path instead.
