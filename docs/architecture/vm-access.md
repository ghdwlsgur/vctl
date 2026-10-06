# Linux VM access

## Goal

Open a shell in an OpenStack Linux VM with `vctl`, without a user-managed SSH
private key or an inbound SSH port. The VM initiates an outbound mTLS session to
the access gateway, which authenticates the operator, checks an explicit shell
grant, and records session start and end events.

## Current boundary

The deployed `vctl-session-agent` is installed on OpenStack physical hosts. Its
protocol supports only fixed, read-only host operations. It does not run inside
VM guests and does not provide a PTY. Installing it on a compute host therefore
does not make that host's VMs accessible.

`vctl ssh --vm <uuid>` is a separate existing path. It creates an ephemeral SSH
key in process memory, asks Vault to sign its public key, and uses the resulting
short-lived SSH certificate. No user private key is stored by `vctl`; the VM
still needs a route to port 22, a matching login account, and trust in the Vault
SSH CA.

## Linux guest session design

The Linux guest agent and gateway PTY path are implemented. Each guest gets a
VM-specific client identity, connects outbound over HTTPS/WSS, and opens a local
login PTY only after the gateway authorizes an operator shell session. The
agent starts `/bin/bash -l` when Bash is installed and falls back to `/bin/sh`.
Shell access currently runs as root and uses a separate `node-access-shell`
grant; the existing `node-access` grant remains for read-only operations. The
gateway records the operator, VM UUID, session ID, start time, end time, and
outcome. Terminal contents are not stored in the current audit schema.

The gateway identifies a guest by deployment ID and Nova instance UUID. A VM
certificate must be bound to that identity; a shared credential in global Nova
vendordata is not acceptable because any guest could copy it and impersonate
another VM.

Open the interactive shell by selecting a VM in `vctl openstack` and pressing
`c`, or pass its Nova UUID directly:

```text
vctl openstack ssh <nova-uuid>
```

The browser supplies the selected VM UUID. The operator does not enter a guest
hostname or Linux login account. The previous `vctl ssh --vm` path remains
available for enrollment and legacy SSH access.

## Enrollment

`vctl node-access install-vm <uuid>` provisions a running guest through the
existing Vault SSH-certificate connector. It needs a one-time path to execute as
root in the guest. The preferred first option is the existing `vctl ssh --vm` Vault
certificate path, where the VM already trusts the CA and the selected login can
use passwordless sudo. If that path is unavailable, the guest must be enrolled
through a rebuilt image, a controlled cloud-init/user-data update followed by a
reboot, or another pre-existing guest-management channel. The compute host's
node agent cannot install software in a guest.

For newly created guests, Nova DynamicJSON can provide a short-lived HMAC grant
bound to the farm, project, and Nova UUID. The guest creates its private key
locally, submits a CSR to the gateway, and receives a client certificate bound
to that UUID. The grant contains no private key or Vault credential. A
farm-wide AppRole secret or shared certificate must never be embedded in
vendordata. The gateway endpoint, VM PKI role, enrollment key, and agent binary
are deployed in SRE core. Nova DynamicJSON is not yet enabled on any farm, so
new VMs will not receive the agent automatically until their Kolla config is
updated. Shutoff VMs can only be enrolled after they are started. The first
rollout targets active Linux VMs; Windows guests require a separate agent and
PTY implementation.

## Fleet rollout state

Rollout targets active Linux VMs whose current records can be verified, whose
Vault-signed SSH certificate login succeeds, and whose account has
passwordless sudo. A VM counts as enrolled only after it reports through the
gateway; shell availability additionally requires a PTY handshake. Stopped
VMs and Windows images need a separate rollout path.

The local Linux container integration test has verified an mTLS VM agent
connection, authenticated operator shell, PTY input/output, and completed
session audit. The live pilot below separately validates the production
ingress, Vault grant, and guest agent path.

Migration 033 is applied to the production database. Gateway image
`node-access-vm-shell-20261002-amd64` is published and running in SRE core at
1/1 replicas. The ingress returns 401 (missing operator bearer token) for the
shell route, confirming the route is live.

At the 2026-10-02 rollout, 14 of 22 active VMs in `sre-0047-epoxy` and 7 of
18 active VMs in `sre-0048-caracal` were enrolled. All 21 enrolled agents
returned `host-status` through the gateway. The new
`vctl openstack ssh <uuid>` command opened `/bin/bash -l` as root on the GitLab
VM and completed a command round trip. Earlier PTY checks also passed on the
development VMs and three SRE workers.

Two deployment issues were found and corrected during the pilot: the first
manual transfer used a macOS binary and systemd rejected it, so the agent was
rebuilt for Linux amd64; then the guest's cloud-init resolver (`8.8.8.8`) could
not resolve the private gateway hostname. Both pilot VMs map
`node-access.sre.local` to the reachable SRE load balancer address
`192.168.201.12` in `/etc/hosts`; the gateway certificate validated for the
hostname. The normal HTTPS polling path and the WebSocket Bash path both work.
The WebSocket clients explicitly negotiate HTTP/1.1 for the Upgrade handshake,
and the Linux PTY integration test passes.

This is a partial rollout across two SRE farms, not all registered farms. The
installer provisions a Linux amd64 agent and a resolvable gateway endpoint for
each guest. Where private DNS is unavailable, it records the gateway's verified
address in the guest's `/etc/hosts`. Windows guests are not supported by this
agent.

On `sre-0047-epoxy`, eight VMs remain unenrolled because SSH authentication,
host-key verification, or tenant bastion authentication failed. On
`sre-0048-caracal`, ten secloudit VMs remain unenrolled because the package
bastion rejected SSH authentication; `wireguard-gw-2` also failed that
preflight. The installer left these VMs unchanged. Other active farms could
not be refreshed from this workstation: their Keystone API timed out or their
Vault credentials were missing, so no stale VM records were used for installs.

The nine operator-supplied Horizon URLs are stored as deployment metadata and
are separate from the Keystone endpoints used for authentication and Nova API
calls. `farm list --json` and `farm show` read the Horizon URL from that field.
