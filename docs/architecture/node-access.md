# Outbound node access

## Current implementation boundary

`internal/nodeaccess` implements the protocol and TLS boundary for the access
gateway and a separate outbound session agent. The gateway is deployed and the
read-only agent has been installed on physical OpenStack hosts. The existing
`vctl-agent node-agent` remains a low-resource status reporter and is not given
a shell, listener, or session workload. Linux VM shells use a distinct systemd
unit and a separate authorization grant.

The protocol uses typed operations (`host.status`, `containers.list`,
`service.status`, and `service.journal`) rather than an operator-provided
command string. Requests carry an ID, protocol version, constrained parameters,
and an expiry no more than two minutes away. The agent must validate every
request before dispatch, enforce output/time limits, and record a result against
the request ID.

## Intended connection flow

```text
vctl operator -- OIDC/Vault identity + command RBAC
        | HTTPS + Vault bearer token
Access Gateway -- inventory lookup + per-node authorization + audit
        | outbound HTTPS/mTLS long poll (node initiated)
session-agent -- fixed operation dispatcher
        | local read-only OS APIs
OpenStack host
```

The node certificate identity is a URI SAN of the form
`spiffe://vctl.local/node/<identity>`. Physical agents use their inventory
hostname; a VM guest agent uses its Nova UUID. The gateway validates the
certificate chain and maps the identity to an active host or VM inventory
record. TLS authentication identifies an agent; it does not authorize an
operator. Operator identity and per-target access are checked independently on
each request.

## Security and deployment decisions

- Keep the status agent's `vctl-node` AppRole and `vctl-status` database role
  unchanged. Do not reuse them to mint certificates or run commands.
- Run the physical-host session agent as a separate systemd unit with a
  dedicated identity and read-only operations. The VM session unit is separate
  and runs as root because it creates a login PTY; it is restricted to VM UUID
  identities and the `node-access-shell` grant.
- Use a dedicated node-access CA with short-lived certificates. Do not reuse
  the SSH signing CA. Host-specific Vault roles, certificate rotation, and the
  root-SSH host installer are implemented. VM guest enrollment is a separate
  step and must use a per-VM identity.
- The gateway must own user authentication, RBAC checks, inventory mapping,
  request expiry, concurrency limits, audit persistence, and cancellation. A
  client certificate alone is not an operator credential.
- The gateway supports interactive Linux PTY sessions over outbound mTLS
  WebSockets. It authorizes each session, limits concurrency and duration, and
  audits session start/end metadata. Terminal contents are not recorded.

## Current code

- `internal/nodeaccess/protocol.go` defines request/result envelopes, strict
  operation and parameter validation, node URI identities, and TLS 1.3
  configuration for outbound agents and mTLS gateway listeners.
- `internal/nodeaccess/agent.go` implements the agent's outbound HTTPS
  long-poll and result channel. `execute.go` dispatches the fixed local
  read-only operations without a shell, with time and output bounds.
- `internal/nodeaccess/gateway.go` provides the HTTP request broker, requires
  injected operator/node authorization and audit adapters, and refuses to
  start without all three. Its pending queue is in memory, so an interrupted
  gateway loses in-flight requests; audit history belongs in the adapter.
- `vctl-agent session-agent` serves fixed host operations and maintains the
  outbound agent stream for VM PTY sessions. `vctl node-access <uuid> shell`
  and `vctl openstack vm connect <uuid>` open an interactive VM shell.
- `vctl node-access <host-or-vm-uuid> <operation>` sends an operator request with the
  current Vault token and is gated by the new `node-access` RBAC command. The
  gateway must independently validate that token and its node grant.
- Concrete Vault/Postgres authorization and audit adapters, the gateway
  executable/deployment, and certificate renewal are implemented. Active VM
  UUIDs can be authorized by the adapter. `vctl node-access install-vm <uuid>`
  installs a per-VM identity and agent through Vault-signed SSH, if the guest
  already trusts the SSH CA and has a login with passwordless sudo. The
  production audit migration must be applied before the gateway can persist VM
  target audit rows.
