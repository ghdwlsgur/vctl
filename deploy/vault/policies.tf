# vctl policies (least privilege). Definitions live in the sibling *.hcl files so
# they read cleanly and stay diffable on their own.
resource "vault_policy" "vctl" {
  for_each = toset([
    "vctl-user",      # team members: ssh sign + ro DB + migrator
    "vctl-admin",     # inventory sync/writes + CA rotation
    "vctl-node",      # node-agent: vctl-status only
    "vctl-collector", # audit daemons: vctl-rw only
    "vctl-host",      # full host stack: vctl-rw + vctl-status
  ])
  name   = each.key
  policy = file("${path.module}/${each.key}.hcl")
}
