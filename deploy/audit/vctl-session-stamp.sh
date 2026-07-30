# shellcheck shell=sh
# /etc/profile.d/vctl-session-stamp.sh
# Record a session marker keyed by certificate serial, from the SSH login shell.
# (sourced; needs no execute bit)
# (Being sourced, this file has no shebang. The directive above tells ShellCheck
#  which dialect to assume so it does not read line 1 as a broken shebang.)
#
# Why profile.d and not PAM: sshd's ExposeAuthInfo puts $SSH_USER_AUTH into the
# session shell's environment only — pam_exec session hooks never receive it
# (verified). The login shell does have it, so the certificate is read here, its
# serial extracted, and a marker written to /run/vctl/sessions/<pid>.json. The
# vctl-watch-sessions daemon turns that marker into an audit_session row.
#
# The marker directory stays root:root 0700. Never widen it to group or world
# writable: a non-root user could then forge or delete another session's marker,
# and audit attribution would be silently wrong rather than missing.
#
# The marker backend currently supports root SSH sessions only. Supporting
# non-root users is not a reason to relax these permissions first — the
# permissions are what makes the attribution trustworthy.
[ -n "${SSH_USER_AUTH:-}" ] && [ -r "$SSH_USER_AUTH" ] || return 0 2>/dev/null

_vctl_serial=""
_vctl_cl=$(grep -m1 'cert-v01@openssh.com' "$SSH_USER_AUTH" 2>/dev/null)
if [ -n "$_vctl_cl" ]; then
  _vctl_t=$(mktemp)
  printf '%s\n' "$_vctl_cl" | sed 's/^publickey //' > "$_vctl_t"
  _vctl_serial=$(ssh-keygen -L -f "$_vctl_t" 2>/dev/null | awk -F'Serial: ' '/Serial:/{print $2;exit}')
  rm -f "$_vctl_t"
fi
_vctl_lp=$PPID
# started is the login time and never changes. Keeping it stable means a
# watch-sessions restart upserts the same session under the same key instead of
# registering a duplicate and leaving a phantom "live" row behind.
_vctl_st=$(date -u +%Y-%m-%dT%H:%M:%SZ)
mkdir -p /run/vctl/sessions 2>/dev/null && cat > "/run/vctl/sessions/${_vctl_lp}.json" 2>/dev/null <<EOF
{"serial":"${_vctl_serial}","login":"$(id -un)","rhost":"${SSH_CONNECTION%% *}","leader_pid":${_vctl_lp},"host":"$(hostname)","started":"${_vctl_st}"}
EOF
unset _vctl_serial _vctl_cl _vctl_t _vctl_lp _vctl_st
