# vctl node-agent

`vctl node-agent` reports lightweight runtime state for hosts already registered
in the central `servers` inventory. It does not create inventory rows. This keeps
the authority split clear:

- `servers`: operator-managed source of truth for connection metadata.
- `server_status`: observed runtime state from the host.

## Install

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

Use `vctl node-agent --once --hostname <inventory-hostname>` for one-shot
testing before enabling the daemon.
