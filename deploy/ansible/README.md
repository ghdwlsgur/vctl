# Fleet onboarding (Ansible)

Playbooks that roll the vctl host stack onto existing servers. They install the
*same* units and scripts that live in `../audit` and `../node` (single source of
truth — no duplicated copies here) plus the SSH CA trust.

| Playbook | What it does |
|---|---|
| `trust-vault-ssh-ca.yml` | Install the operator-supplied `files/vault-ca.pub` as system-wide `TrustedUserCAKeys` in `/etc/ssh/sshd_config.d/10-vault-ca.conf` (same as `vctl trust-ca`, in bulk). |
| `site.yml` | Install node-agent (runtime status) by default. The collector + watch-sessions audit stack, `vctl-host` AppRole, and Tetragon are explicit opt-ins via `vctl_host_audit_stack=true`. |
| `openstack-vendordata.yml` | Install the same CA trust into an OpenStack farm's Nova vendordata, so a **new VM** trusts vctl certificates from first boot. See below. |
| `openstack-vm-agent-vendordata.yml` | Stage per-farm Nova DynamicJSON settings so new Linux VMs fetch a short-lived, VM UUID-bound enrollment grant from the access gateway. |
| `kolla-nova-mount-propagation.yml` | Keep kolla's nova `/var/lib/nova/mnt` bind from doubling on every container start, without hiding any NFS: enables a boot-time unit (never started live). Optionally collapses layers that already stacked. See below. |

## Kolla nova mount propagation

On docker compute hosts kolla binds `/var/lib/nova/mnt:/var/lib/nova/mnt:shared`
inside the `nova_compute` volume, which sits in `/`'s shared peer group. The bind
propagates back to the host and every later container start copies it again, so
`/var/lib/nova/mnt` doubles per start until a reboot (1023 layers on the worst
host, 2026-10-19).

The playbook installs `nova-mnt-private.service`, which at boot, before docker,
makes only `<docker root>/volumes/nova_compute/_data/mnt` a private self-bind.
The instances NFS under `_data/instances` and the cinder shares under
`/var/lib/nova/mnt` keep reaching the host and every nova container, including
when they are remounted later. It is enabled, **never started**: applied while
containers run it hides the cinder shares inside them, and the script refuses
whenever a container is running. It takes effect at the next reboot.

**2026-10-20 incident.** The first version made the whole volume a
non-recursive private bind, live. It propagated over `/var/lib/nova` inside the
running containers and hid the instances NFS and the cinder shares; running
VMs kept their open disks, and it was undone on all ten hosts. Mounts are now
verified by walking the path (`stat -f <dir>/.` inside each container), not by
counting `mountinfo` lines — which is how that version passed.

```bash
ansible-playbook kolla-nova-mount-propagation.yml -l <host> --check --diff
ansible-playbook kolla-nova-mount-propagation.yml -l <host>
ansible-playbook kolla-nova-mount-propagation.yml -l <host> -e nova_mnt_collapse=true   # collapse existing layers
```

## Nova DynamicJSON VM enrollment

The access gateway is deployed at `https://node-access.sre.local`. This play
stages a `cloud-init` DynamicJSON target in the Kolla Nova config for each farm.
Nova authenticates to that farm's Keystone as its existing `nova` service user;
the play reads `nova_keystone_password` from the farm's `/etc/kolla/passwords.yml`
and sets its keys in `nova/nova-api.conf` and `nova/nova-metadata.conf` under
`node_custom_config`. Secret-bearing tasks hide their output and diffs, so
`--check --diff` reports which files would change but not the lines.

- **Ownership.** Kolla's `merge_configs` runs as the `kolla` user and skips an
  override it cannot read while still ending `failed=0`. The files carry the
  Nova service password, so they are `kolla:kolla 0600` (override with
  `vendordata_kolla_user` / `vendordata_kolla_group`), never `root:root 0600`.
- **Existing settings.** The play edits one key at a time with
  `community.general.ini_file`; everything else in those files is left alone.
  It stops if `vendordata_providers` is set to anything other than
  `StaticJSON` (Nova's default) or the play's own value, or if
  `vendordata_dynamic_targets` points elsewhere. Override only after checking
  what depends on it: `-e vendordata_force=true`.
- **Rollback.** `-e state=absent` removes only the play's `[api]` keys and the
  `[vendordata_dynamic_auth]` section, and deletes an override file only when
  nothing else is left in it.

Install the collection on the controller first:
`ansible-galaxy collection install -r requirements.yml`.

The inventory variable `openstack_deployment_id` must exactly match the Keystone
ID shown by `vctl openstack farm list` (for example, `172.16.0.245:5000`). It is
used both to select the registered farm at the gateway and to construct the
Keystone v3 auth URL. Do not use the Horizon URL here; Horizon and Keystone are
separate endpoints.

The play checks from the Kolla deployment host that the gateway health endpoint
has a valid HTTPS certificate, and that Keystone issues a service token whose
user, project and admin role match the gateway's validator. Ensure the Nova API
containers also trust the gateway's issuing CA. Kolla can add CA files from
`/etc/kolla/certificates/ca` to service containers when
`kolla_copy_ca_into_containers` is enabled. Alternatively, set
`vendordata_dynamic_ssl_certfile` to a CA bundle path inside the Nova container.
TLS verification is never disabled.

The play stages configuration only. Review the diff, run `kolla-ansible
genconfig -t nova`, review generated Nova config, then reconfigure the metadata
responder in a maintenance window. Releases with a separate `nova-metadata`
service should reconfigure that responder; older releases serve metadata from
`nova-api`, which also serves the Compute API. The existing static vendordata
file remains enabled for its current SSH CA trust payload.

At the latest inventory read (2026-10-02), the active deployment IDs were:

| Farm | Keystone deployment ID |
|---|---|
| `ai/native-1x4-dalmatian` | `172.16.0.150:5000` |
| `hybrid-0026-epoxy` | `172.16.0.111:5000` |
| `hybrid-1x2-epoxy` | `172.17.0.115:5000` |
| `incheon-main-farm` | `172.16.0.10:5000` |
| `infra-3x5-epoxy` | `172.16.0.245:5000` |
| `infra-3x5-gazpacho` | `172.17.0.87:5000` |
| `posco-infra-dev-farm` | `172.16.0.21:5000` |
| `sre-0047-epoxy` | `192.168.201.130:5000` |
| `sre-0048-caracal` | `192.168.201.90:5000` |

The two hybrid farms marked `retired` in inventory were excluded. Inventory IDs
and active state can change; read `vctl openstack farm list --json` before each
rollout. This config provisions only **new** guests; it does not retrofit
already-running VMs.

Run for one farm first, using a deploy host in `openstack_deploy` with the
farm-specific variables in inventory:

```bash
ansible-playbook -i inventory/hosts.ini openstack-vm-agent-vendordata.yml \
    -l infra_epoxy
```

After the canary succeeds and its generated `vendor_data2.json` contains a
`cloud-init` entry, repeat for the remaining active farm deploy hosts. The
actual deploy-host addresses are intentionally kept in the ignored
`inventory/hosts.ini` file.

For a new canary VM, check the response without displaying its short-lived
enrollment grant:

```bash
curl -fsS http://169.254.169.254/openstack/latest/vendor_data2.json \
    | jq -e '."cloud-init" | startswith("#cloud-config")' >/dev/null
cloud-init status --wait
systemctl is-active vctl-vm-session-agent.service
```

Then verify the VM appears as connected through `vctl openstack` and can open a
shell through the gateway. `vendor_data2.json` is metadata and contains the
one-hour bootstrap grant; do not print or retain its full response.

## Nova vendordata (new VMs)

`trust-vault-ssh-ca.yml` onboards a machine that already exists. A VM created
five minutes from now needs the same trust before anyone can reach it, and the
only thing running at that point is cloud-init. Nova's vendordata is what hands
it the cloud-config.

The CA public key is **not** in this repo. It is read from Vault
(`ssh/config/ca`) each run — the same key `vctl trust-ca` installs — and rendered
into `templates/vendordata-cloud-config.yml.j2`. One source of truth for the key,
so a rotation cannot leave a stale copy behind in git.

```bash
# one farm; deploy host and control hosts are often the same machine
ansible-playbook -i inventory/hosts.ini openstack-vendordata.yml -l lab_a

# control node without Vault access (an override, not a fallback)
ansible-playbook -i inventory/hosts.ini openstack-vendordata.yml \
    -e vendordata_ca_pub_file=files/vault-ca.pub
```

Two things about this are not obvious, and both have bitten already.

**Which service answers the VM is not the same on every farm.** A VM asking
169.254.169.254 is proxied by the neutron metadata agent to port 8775. On newer
releases that port belongs to `nova_metadata`; on older ones there is no such
service and `nova_api` serves both APIs from one apache config, a vhost on 8774
and another on 8775. Configuring the wrong one looks like it worked — measured on
a farm where a `nova-api.conf` override had been in place for a month,
`vendor_data.json` returned `{}` while `meta_data.json` returned real data for the
same signed request. The play derives the answering service rather than assuming
it, and prints which one it picked.

**Whether the file reaches nova-metadata depends on the kolla-ansible version.**
Measured across the deploy hosts here, not read from release notes:

| kolla-ansible | nova-metadata a service? | Where the file is copied | Net effect |
|---|---|---|---|
| 17.3.1, 18.1.0, 18.8.0 | no — `nova_api` serves 8775 | `nova-api` | copy target and answering service agree; nothing special needed |
| 20.2.0 | yes | `nova-api` only (hardcoded) | **trap** — see below |
| 20.4.0 | yes | loops `nova-metadata`, `nova-api` | fixed upstream |

On 20.2.0 that combination is a trap: `nova-metadata.json.j2` declares a mount
for the file that is **not** marked optional, and `kolla_set_configs` raises
`MissingRequiredSource` on a non-optional missing source. So once the file exists
in `node_custom_config`, a plain reconfigure leaves `nova_metadata` unable to
start. This play places the file in every Nova service directory whose
`config.json` declares it, and refuses to remove one while a `config.json` still
does — a no-op on 20.4.0, and the difference between working and not on 20.2.0.

On the releases with no separate `nova-metadata`, the catch is different: the
restart that makes the file take effect is a restart of `nova_api`, which is the
compute API too. Stage with `vendordata_restart=false` and restart in a window.

A deploy host can have more than one kolla-ansible venv. Check which one the last
run used before assuming: one farm here reconfigured 2025.1 containers from a
2024.1 venv, which is why its `nova-metadata` config sat a month behind its
`nova-api` config with nobody noticing.

Order for a farm that has never had this, and the order matters:

```bash
# 1. source of truth + the file placed where genconfig is about to declare it
ansible-playbook -i inventory/hosts.ini openstack-vendordata.yml -l lab_a \
    -e '{"vendordata_extra_dirs":["/etc/kolla/nova-metadata"]}'

# 2. back up, regenerate, diff before believing it
#    (genconfig rewrites config, it does not restart containers)
kolla-ansible genconfig -t nova --limit <host>

# 3. restart nova_metadata (stop then start), then verify
```

Placing the file first is what makes this safe. `genconfig` is the step that
makes `nova-metadata` declare the mount, and it never writes the file itself —
so doing it the other way round leaves a window where the deployed `config.json`
names a file that is not there, and any restart in that window leaves the
container unable to start. The play verifies that `nova_metadata` can actually
read the file, and says so when it cannot.

One thing to expect at step 2 on a farm that has drifted: `genconfig` regenerates
*everything* for the services it touches, not just the vendordata. If a service's
config is months old, that whole diff lands at once. Back up the service
directory and read the diff before restarting anything.

## Prerequisites

- The AppRole the host uses exists in Vault (see the `vault-iac` repo). Which one
  depends on `vctl_host_audit_stack`:
  - `vctl_host_audit_stack=true` (explicit opt-in) -> **`vctl-host`** (`vctl-audit-ingest` + `vctl-status`):
    full stack (collector + watch-sessions + node-agent).
  - `vctl_host_audit_stack=false` (default) → **`vctl-node`** (`vctl-status` only): node-agent ONLY,
    no DB write — least privilege for liveness-only hosts.
  The playbook reads the role's `role_id` and mints a per-host `secret_id` from the
  **control node's** `VAULT_ADDR`/`VAULT_TOKEN`, so run with a token allowed to do
  `vault read auth/approle/role/<role>/role-id` and
  `vault write -f auth/approle/role/<role>/secret-id` (role = vctl-host or vctl-node).
- The release **linux binary** placed at `files/vctl` (gitignored):
  `gh release download vX.Y.Z -p 'vctl_*_linux_amd64.tar.gz' && tar -xzf … -C files/`
  (or switch the play to install the `.deb`/`.rpm` from the release).
  First verify the downloaded archive against release `checksums.txt`, then set
  `vctl_host_bin_sha256` to `sha256sum files/vctl` (the extracted binary digest).
  The role verifies those installed bytes before restarting any daemon.
- The current Vault SSH CA **public key** placed at `files/vault-ca.pub`
  (gitignored). Verify its fingerprint through a trusted channel before running
  `trust-vault-ssh-ca.yml`.
- Hosts already trust the SSH CA (`trust-vault-ssh-ca.yml` or `vctl trust-ca`).
  This is a system-wide sshd `TrustedUserCAKeys` trust, not a copy in each
  account's `authorized_keys`. Keep host clocks NTP-synchronized: a clock that
  lags the Vault signer causes sshd to reject a fresh certificate as `not yet valid`.

## Run (canary first, then waves)

```bash
# one canary host
ansible-playbook -i inventory.ini site.yml -l <canary>

# a wave / group
ansible-playbook -i inventory.ini site.yml -l seoul_wave1

# explicit full audit-stack canary (never enable fleet-wide implicitly)
ansible-playbook -i inventory.ini site.yml -l <canary> -e vctl_host_audit_stack=true

# non-seoul networks: point hosts at the right LB for *.sre.local
ansible-playbook -i inventory.ini site.yml -l incheon_onprem -e vctl_host_sre_lb_ip=<lb-ip>

# k8s nodes: skip the bare-VM Tetragon install (use a DaemonSet instead)
ansible-playbook -i inventory.ini site.yml -l k8s_nodes -e vctl_host_install_tetragon=false

# rollback
ansible-playbook -i inventory.ini site.yml -l <host> -e vctl_host_state=absent
```

`site.yml` advances in 20% waves and stops on the first failed host. Override
with `-e vctl_rollout_serial=1` for a strict one-host canary. Every enabled
service must pass `systemctl is-active` after its handlers run.

`vctl_host_enable_services` stays effectively gated on the `secret_id` being present, so a
host never crash-loops before its credential is in place. node-agent and
watch-sessions do **not** need Tetragon; only the collector does.

SSH host-key checking is enabled. Populate the control user's `known_hosts`
through a trusted channel before onboarding a server. Re-run the play regularly.
Secret IDs no longer expire silently, but the role rotates them after 21 days
to bound the lifetime of a leaked credential.

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
