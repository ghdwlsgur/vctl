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
# whenever a container using the nova_compute volume runs; it is meant to run
# from nova-mnt-private.service, ordered before docker.service at boot, or by
# hand on a host whose nova containers are stopped.
set -u
# Only containers that mount the nova_compute volume can be covered; others
# (keystone, haproxy, ...) may keep running. At boot docker is not up yet and
# this finds nothing.
if command -v docker >/dev/null 2>&1 && [ -n "$(docker ps -q --filter volume=nova_compute 2>/dev/null)" ]; then
  echo "nova-mnt-private: refused, containers using the nova_compute volume are running (stop nova_compute, nova_libvirt and nova_ssh first, or let it run at boot)" >&2
  exit 1
fi
root=$(sed -n 's/.*"data-root" *: *"\([^"]*\)".*/\1/p' /etc/docker/daemon.json 2>/dev/null | head -1)
# Resolve symlinks: sre-srv-0047 has /var/lib/docker -> /home/docker, and
# mountinfo records the resolved path.
V="$(readlink -f "${root:-/var/lib/docker}")/volumes/nova_compute/_data"
[ -d "$V" ] || { echo "nova-mnt-private: no nova_compute volume at $V; nothing to do"; exit 0; }
layers() { awk -v p="$V/mnt" '$5==p' /proc/self/mountinfo | wc -l; }
if [ "$(layers)" -eq 1 ] && awk -v p="$V/mnt" '$5==p {print $7}' /proc/self/mountinfo | grep -qx -- '-'; then
  echo "nova-mnt-private: $V/mnt is already a private bind; leaving it"; exit 0
fi
# Anything else mounted here is what earlier container starts propagated back
# (the stack this exists to stop). With no nova container running it holds
# nothing in use; clear it so the private bind is the only layer. Skipping it
# instead — "already a mount" — left the shared copy on top and the stack kept
# doubling (sre-srv-0041/0042, 2026-10-20).
n=0
while [ "$(layers)" -gt 0 ] && [ $n -lt 4096 ]; do umount -l "$V/mnt" || break; n=$((n+1)); done
[ $n -gt 0 ] && echo "nova-mnt-private: cleared $n leftover layer(s) at $V/mnt"
mkdir -p "$V/mnt"
mount --bind "$V/mnt" "$V/mnt"
mount --make-private "$V/mnt"
echo "nova-mnt-private: $V/mnt is now a private bind"
