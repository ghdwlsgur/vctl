# SSH CA — signs the per-connection certificates `vctl ssh` presents.
resource "vault_mount" "ssh" {
  path        = "ssh"
  type        = "ssh"
  description = "SSH CA — per-connection SSH cert signing for vctl"
}

resource "vault_ssh_secret_backend_ca" "ssh" {
  backend              = vault_mount.ssh.path
  generate_signing_key = true
  # Regenerating mints a NEW CA key → every host's TrustedUserCAKeys must be
  # re-onboarded (vctl trust-ca). Ignore drift so apply never silently rotates it;
  # restore a backed-up key by importing this resource instead.
  lifecycle {
    ignore_changes = [generate_signing_key]
  }
}

resource "vault_ssh_secret_backend_role" "sre_core" {
  name                    = "sre-core"
  backend                 = vault_mount.ssh.path
  key_type                = "ca"
  allow_user_certificates = true
  allowed_users           = "ubuntu,rocky,root"
  default_user            = "ubuntu"
  allowed_extensions      = "permit-pty,permit-port-forwarding,permit-agent-forwarding,permit-X11-forwarding,permit-user-rc"
  default_extensions      = { "permit-pty" = "" }
  ttl                     = "1800" # 30m
  max_ttl                 = "7200" # 2h
}

output "ssh_ca_public_key" {
  description = "CA public key for hosts' TrustedUserCAKeys / golden image (not secret)"
  value       = vault_ssh_secret_backend_ca.ssh.public_key
}
