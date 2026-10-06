# vctl access gateway pilot

The pilot gateway is a single replica because its in-flight request broker is
in memory. It authenticates operator Vault tokens independently, checks
`node-access`/`node-access-shell` grants against active host or VM inventory,
requires a verified node client certificate at ingress, and appends lifecycle
metadata through a dedicated insert-only Postgres role. Linux VM shells use
outbound mTLS WebSockets and a root PTY. Session metadata is audited; terminal
contents are not recorded.

## Required platform setup

The following are prerequisites for the manifest in `k8s.yaml`:

1. Publish `harbor.sre.local/sre/vctl-access-gateway:<tag>` and pin the image
   digest in the Deployment. The VM-enrollment build is published and running
   in SRE core.
2. The live `vctl-pg` connection allows `vctl-node-access-audit`, and its Vault
   database role exists. Ensure the `vctl_node_access_audit` NOLOGIN group exists with INSERT only on
   `node_access_audit`; the migration grants it when present, and
   `postgres-groups.sh` bootstraps it for managed recovery. The live Vault role
   has an idempotent bootstrap statement for the initial credential issuance.
3. The gateway's Kubernetes auth role and Vault policy are provisioned. The
   constrained `pki_sre_int/vctl-vm-agent` role and sign-only gateway policy
   are live.
4. Database migrations 032 and 033 are applied in production; 033 extends
   audit targets to Nova UUIDs. Create secret
   `vctl-node-access-client-ca` in namespace `vctl` with only the root CA certificate in key `ca.crt` for ingress-nginx. Create
   `vctl-node-access-gateway-ca` with the root and issuing intermediate in
   `ca.crt` for the gateway's forwarded-certificate verification. The CA must
   sign a distinct client certificate per inventory hostname with URI SAN
   `spiffe://vctl.local/node/<inventory-hostname>`.
5. The VM enrollment HMAC key is stored at `kv/teams/sre/vctl-vm-enrollment`
   and in Kubernetes Secret `vctl-vm-enrollment` in namespace `vctl`.
6. Ensure `node-access.sre.local` resolves to the existing ingress address and
   that the `vault-issuer` ClusterIssuer can issue the gateway server
   certificate.

## Current rollout status

As of 2026-10-03, the SRE core gateway is Ready at one replica, serves the
published immutable image digest, and passes HTTPS health checks. Unauthenticated
vendordata and enrollment requests return 401; the public agent binary route
returns a Linux amd64 executable.

Nova DynamicJSON is not yet enabled on any OpenStack farm. The Kolla staging
playbook is `deploy/ansible/openstack-vm-agent-vendordata.yml`. Applying it needs
one real Kolla config-source host per active farm in the ignored Ansible
inventory and access to that farm's Kolla files. The local inventory currently
has no `openstack_deploy` hosts.

Ingress terminates HTTPS and performs optional client-certificate validation
because the operator API uses a Vault bearer token. For agent requests it
passes the URL-escaped client certificate to the gateway, which verifies the
chain again. The NetworkPolicy limits the plaintext pod Service to ingress
controller pods.

## Pilot node enrollment

The host-side `vctl-session-agent` unit is separate from `vctl-node-agent`.
Each node uses a dedicated AppRole that can issue only its own fixed-identity
certificate. Install its role-id and secret-id under `/etc/vctl/session-agent/`
with root-only permissions. The agent issues its first certificate and renews
it when fewer than 10 days remain, checking twice daily. New keys and chains
are stored under `/var/lib/vctl-session-agent/`; the running process adopts a
new identity without restarting. Configure `VCTL_ACCESS_GATEWAY`, `VAULT_ADDR`,
`VCTL_RENEW_PKI_MOUNT`, `VCTL_RENEW_PKI_ROLE`, `VCTL_RENEW_COMMON_NAME`, and
`VCTL_RENEW_URI_SAN` in `/etc/vctl/session-agent.env`. Enable the service only
after the gateway is Ready and the host-specific PKI role and AppRole exist.

For an inventory host with root SSH access and an operator identity allowed to
manage AppRoles/PKI roles, enroll it with:

```text
vctl node-access install sre-srv-0050 --binary ./vctl-agent
```

The command creates the host-scoped Vault policy, AppRole and PKI role, issues
the first certificate, and installs the agent and systemd unit over the normal
audited SSH path. Set Terraform variable `node_access_hosts` to the same host
set so the live roles are represented in infrastructure as code.

Validate with a read-only operation:

```text
vctl node-access sre-srv-0047 host-status
vctl node-access sre-srv-0047 service-status --service sshd.service
```

Do not enable the host unit while any prerequisite above is missing. The
gateway exposes typed read-only host operations and an interactive PTY for
enrolled Linux VM UUIDs, protected by the separate `node-access-shell` grant.
