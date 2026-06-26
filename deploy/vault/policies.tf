# vctl policies (least privilege). Definitions live in the sibling *.hcl files so
# they read cleanly and stay diffable on their own.
resource "vault_policy" "vctl" {
  for_each = toset([
    "vctl-user",      # baseline: ssh-sign capability + ro DB reads (app gates ssh)
    "vctl-admin",     # inventory writes + CA + RBAC management
    "vctl-node",      # node-agent: vctl-status only
    "vctl-collector", # audit daemons: vctl-rw only
    "vctl-host",      # full host stack: vctl-rw + vctl-status
  ])
  name   = each.key
  policy = file("${path.module}/${each.key}.hcl")
}
