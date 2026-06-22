#!/bin/sh
# Runs after the vctl package is removed. Only tear down on a real removal, never
# on an upgrade: deb passes "upgrade" and rpm passes "1" while upgrading, and we
# must leave running agents alone in that case.
set -e

case "$1" in
    remove|purge|0)
        systemctl disable --now vctl-collect vctl-watch-sessions vctl-node-agent 2>/dev/null || true
        systemctl daemon-reload 2>/dev/null || true
        # Credentials and state under /etc/vctl and /var/lib/vctl are intentionally
        # left in place so a reinstall keeps working; remove them by hand to purge.
        ;;
esac

exit 0
