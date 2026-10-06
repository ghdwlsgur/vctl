# Access gateway service identity: validate presented human Vault tokens,
# resolve inventory/RBAC through vctl-ro, and append operation audit metadata.
path "database/creds/vctl-ro" {
  capabilities = ["read"]
}

path "database/creds/vctl-node-access-audit" {
  capabilities = ["read"]
}

# Used only by the Nova vendordata enrollment path after it validates a
# Keystone-authenticated DynamicJSON request and derives identity from the
# provider-supplied instance UUID.
path "pki_sre_int/sign/vctl-vm-agent" {
  capabilities = ["update"]
}

path "auth/token/lookup-self" {
  capabilities = ["read"]
}

path "auth/token/renew-self" {
  capabilities = ["update"]
}
