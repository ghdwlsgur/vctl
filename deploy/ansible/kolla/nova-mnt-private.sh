#!/usr/bin/env bash
# Boot-time only: make <docker root>/volumes/nova_compute/_data/mnt a private
# self-bind before any nova container starts, so kolla's
# /var/lib/nova/mnt:/var/lib/nova/mnt:shared bind no longer propagates back to
# the host and doubles on every container start.
#
# Only _data/mnt is touched. The instances NFS under _data/instances and the
# cinder shares under /var/lib/nova/mnt keep propagating to the host and every
# nova container — verified by path walk in a docker:dind reproduction of the
# SRE compute hosts (container restarts, libvirt restart, a new share mounted
# by nova_compute, the instances NFS and a cinder share remounted on the host).
#
# NEVER while containers run: applied live, the new mount propagates over
# /var/lib/nova/mnt inside the running containers and hides the cinder shares
# (the same class of failure as the 2026-10-20 incident). So this refuses
# whenever docker has a running container; it is meant to run from
# nova-mnt-private.service, ordered before docker.service at boot.
set -u
if command -v docker >/dev/null 2>&1 && [ -n "$(docker ps -q 2>/dev/null)" ]; then
  echo "nova-mnt-private: refused, containers are running; this only applies at boot" >&2
  exit 1
fi
root=$(sed -n 's/.*"data-root" *: *"\([^"]*\)".*/\1/p' /etc/docker/daemon.json 2>/dev/null | head -1)
# Resolve symlinks: sre-srv-0047 has /var/lib/docker -> /home/docker, and
# mountinfo records the resolved path.
V="$(readlink -f "${root:-/var/lib/docker}")/volumes/nova_compute/_data"
[ -d "$V" ] || { echo "nova-mnt-private: no nova_compute volume at $V; nothing to do"; exit 0; }
if awk -v p="$V/mnt" '$5==p' /proc/self/mountinfo | grep -q .; then
  echo "nova-mnt-private: $V/mnt is already a mount; leaving it"; exit 0
fi
mkdir -p "$V/mnt"
mount --bind "$V/mnt" "$V/mnt"
mount --make-private "$V/mnt"
echo "nova-mnt-private: $V/mnt is now a private bind"
