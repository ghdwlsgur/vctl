# Every enrolled host gets a unique node identity and a PKI role that can issue
# only that identity. The matching AppRole policy can call only this role.
resource "vault_pki_secret_backend_role" "node_access" {
  for_each = var.node_access_hosts

  backend                     = "pki_sre_int"
  name                        = "vctl-node-access-${each.value}"
  allowed_domains             = ["${each.value}.sre.local"]
  allowed_uri_sans            = ["spiffe://vctl.local/node/${each.value}"]
  allow_bare_domains          = true
  allow_subdomains            = false
  allow_glob_domains          = false
  allow_any_name              = false
  allow_ip_sans               = false
  allow_localhost             = false
  allow_wildcard_certificates = false
  client_flag                 = true
  server_flag                 = false
  key_type                    = "ec"
  key_bits                    = 256
  ext_key_usage               = ["ClientAuth"]
  ttl                         = "720h"
  max_ttl                     = "720h"
}

# Nova DynamicJSON enrollment uses a single constrained role for VM agents.
# The issuer service validates the farm's Nova service token and constructs the
# exact UUID based names before calling this endpoint. This role accepts only
# client certificates beneath the VM namespace; wildcard certificates and
# server authentication remain disabled.
resource "vault_pki_secret_backend_role" "vm_agent" {
  backend                     = "pki_sre_int"
  name                        = "vctl-vm-agent"
  allowed_domains             = ["vm.sre.local"]
  allow_bare_domains          = false
  allow_subdomains            = true
  allow_glob_domains          = false
  allow_any_name              = false
  allow_ip_sans               = false
  allow_localhost             = false
  allow_wildcard_certificates = false
  allowed_uri_sans            = ["spiffe://vctl.local/vm/*"]
  client_flag                 = true
  server_flag                 = false
  key_type                    = "ec"
  key_bits                    = 256
  ext_key_usage               = ["ClientAuth"]
  ttl                         = "720h"
  max_ttl                     = "720h"
}
