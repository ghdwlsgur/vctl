# vctl policies (least privilege). Definitions live in the sibling *.hcl files so
# they read cleanly and stay diffable on their own.
resource "vault_policy" "vctl" {
  for_each = toset([
    "vctl-user",           # baseline: inventory/RBAC reads + self-registration
    "vctl-ssh",            # SSH signing + access-log writes
    "vctl-auditor",        # audit/session reads
    "vctl-admin",          # inventory/RBAC writes + migration/CA operations
    "vctl-node",           # node-agent: vctl-status only
    "vctl-access-gateway", # operator token validation + inventory read + node access audit append
    "vctl-collector",      # audit daemons: append/session lifecycle only
    "vctl-host",           # full host stack: audit ingest + status
    "vctl-pruner",         # retention job: audit row deletion only
  ])
  name   = each.key
  policy = file("${path.module}/${each.key}.hcl")
}

resource "vault_policy" "node_access" {
  for_each = var.node_access_hosts
  name     = "vctl-node-access-${each.value}"
  policy   = <<-EOT
    path "pki_sre_int/issue/vctl-node-access-${each.value}" {
      capabilities = ["update"]
    }
  EOT
}
