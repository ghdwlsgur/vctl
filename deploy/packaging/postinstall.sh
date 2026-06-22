#!/bin/sh
# Runs after the vctl package is installed or upgraded (deb: configure, rpm: 1/2).
# Deliberately does NOT enable the host agents: they need AppRole credentials and
# *.sre.local name resolution first, so enabling is an explicit operator step.
set -e

# Credential drop-point and daemon state/home. The services run as root today;
# 0700 keeps the AppRole secret-id readable only by root.
install -d -m 0700 /etc/vctl
install -d -m 0750 /var/lib/vctl

# Pick up the new/changed unit files.
systemctl daemon-reload 2>/dev/null || true

# The sshd snippet (ExposeAuthInfo) only takes effect after a reload. Reload only
# when sshd is running and the merged config still validates, so a bad drop-in can
# never take SSH down on a package install.
if command -v sshd >/dev/null 2>&1 && sshd -t >/dev/null 2>&1; then
    systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
fi

cat <<'EOF'
vctl installed. The host audit/status agents are NOT enabled automatically.
To turn them on for this host:
  1) Place AppRole credentials:  /etc/vctl/role-id  and  /etc/vctl/secret-id
  2) Ensure *.sre.local resolves (vault.sre.local, vctl-postgres.sre.local)
  3) Enable the agent(s) you want:
       systemctl enable --now vctl-node-agent       # runtime host status
       systemctl enable --now vctl-watch-sessions   # SSH session registrar
       systemctl enable --now vctl-collect          # kernel audit (requires tetragon)
EOF

exit 0
