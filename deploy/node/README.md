# vctl node-agent

`vctl-agent node-agent` (the fleet binary; the same command exists on the full
CLI as `vctl node-agent`) reports lightweight runtime state for hosts already registered
in the central `servers` inventory. It does not create inventory rows. This keeps
the authority split clear:

- `servers`: operator-managed source of truth for connection metadata.
- `server_status`: observed runtime state from the host.

## Outbound access agent (not yet deployable)

The separate `vctl-agent session-agent` process and unit are packaged as an
implementation slice for the node-initiated mTLS channel. Do not enable the
unit yet: a production gateway, node certificate enrollment/rotation, and the
Vault/Postgres authorization and audit adapters are not present. The unit
expects `/etc/vctl/session-agent.env` to define `VCTL_ACCESS_GATEWAY` and
short-lived node identity files under `/etc/vctl/session-agent/`.

The current fixed dispatcher supports read-only host load, Podman container
listing, systemd service status, and bounded service journal reads. It does
not offer an interactive shell. See
`/usr/share/doc/vctl/node-access-README.md` for the trust and deployment
boundary.

## Install

The `vctl` `.deb`/`.rpm` package already places the binary and
`vctl-node-agent.service` (see `deploy/audit/README.md` → *Install via package*).
With the package installed, only steps 1–3 below remain, then
`systemctl enable --now vctl-node-agent`. The numbered steps document the manual
path and what the package provides.

1. Run DB migrations with an admin token:

   ```bash
   vctl sync --migrate
   ```

2. Create an AppRole whose token has the `vctl-node` policy. The policy may read
   only `database/creds/vctl-status` plus token self-lookup/renew.

3. Place the AppRole files on the host:

   ```text
   /etc/vctl/role-id
   /etc/vctl/secret-id
   ```

4. Install `vctl-node-agent.service` into `/etc/systemd/system/` and start it:

   ```bash
   systemctl daemon-reload
   systemctl enable --now vctl-node-agent
   ```

## Resource Profile

The service is intentionally small:

- heartbeat interval: `5m`
- `CPUQuota=2%`
- `MemoryMax=48M`
- per-unit journal burst: `200/30s`

Use `vctl-agent node-agent --once --hostname <inventory-hostname>` for one-shot
testing before enabling the daemon.
