#!/bin/sh
# PAM session-open hook: on SSH login, record a marker mapping this session's
# leader pid -> SSH cert serial, so the vctl collector can attribute kernel
# events to a human. Drops a local marker only; it never touches Vault/DB.
#
# Wire in /etc/pam.d/sshd:
#   session optional pam_exec.so /usr/local/sbin/pam-session-stamp.sh
#
# Requires sshd `ExposeAuthInfo yes` (sets $SSH_USER_AUTH).

set -eu

[ "${PAM_TYPE:-}" = "open_session" ] || exit 0
[ -n "${SSH_USER_AUTH:-}" ] && [ -r "$SSH_USER_AUTH" ] || exit 0

MARKER_DIR=/run/vctl/sessions
mkdir -p "$MARKER_DIR"

# $SSH_USER_AUTH holds lines like: "publickey ssh-ed25519-cert-v01@openssh.com AAAA..."
# Extract the certificate and read its serial with ssh-keygen -L.
serial=""
cert_line=$(grep -m1 'cert-v01@openssh.com' "$SSH_USER_AUTH" 2>/dev/null || true)
if [ -n "$cert_line" ]; then
    tmp=$(mktemp)
    # drop the leading "publickey " keyword, keep "<type> <blob>"
    echo "$cert_line" | sed 's/^publickey //' > "$tmp"
    serial=$(ssh-keygen -L -f "$tmp" 2>/dev/null | awk -F'Serial: ' '/Serial:/ {print $2; exit}')
    rm -f "$tmp"
fi

# Session leader pid: this script's parent is the sshd session process.
leader_pid=$PPID

cat > "$MARKER_DIR/${leader_pid}.json" <<EOF
{"serial":"${serial}","login":"${PAM_USER:-}","rhost":"${PAM_RHOST:-}","leader_pid":${leader_pid},"host":"$(hostname)"}
EOF

exit 0
