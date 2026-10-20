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
root=$(sed -n 's/.*"data-root" *: *"\([^"]*\)".*/\1/p' /etc/docker/daemon.json 2>/dev/null | head -1)
# Resolve symlinks: sre-srv-0047 has /var/lib/docker -> /home/docker, and
# mountinfo records the resolved path.
V="$(readlink -f "${root:-/var/lib/docker}")/volumes/nova_compute/_data"
[ -d "$V" ] || { echo "nova-mnt-private: no nova_compute volume at $V; nothing to do"; exit 0; }
layers() { awk -v p="$V/mnt" '$5==p' /proc/self/mountinfo | wc -l; }
prop() { awk -v p="$V/mnt" '$5==p {print $7}' /proc/self/mountinfo | tail -1; }
if [ "$(layers)" -eq 1 ] && [ "$(prop)" = "-" ]; then
  echo "nova-mnt-private: $V/mnt is already private; leaving it"; exit 0
fi
# With nova containers running, a NEW mount here propagates over
# /var/lib/nova/mnt inside them and hides the cinder shares (reproduced). Only
# one thing is safe then: when exactly one mount sits here — what is left after
# kolla/nova-mnt-collapse.sh — change its propagation to private. That creates
# no mount, so nothing in the running containers moves; containers started
# afterwards copy it private and stop stacking (reproduced with an instances
# NFS, a cinder share and open files: nothing hidden, 2 layers through
# restarts, new and remounted shares visible).
if command -v docker >/dev/null 2>&1 && [ -n "$(docker ps -q --filter volume=nova_compute 2>/dev/null)" ]; then
  if [ "$(layers)" -eq 1 ]; then
    mount --make-private "$V/mnt"
    echo "nova-mnt-private: made the existing $V/mnt mount private (containers running, no new mount)"
    exit 0
  fi
  echo "nova-mnt-private: refused, nova containers are running and $V/mnt has $(layers) layer(s); collapse first (kolla/nova-mnt-collapse.sh) or let it run at boot" >&2
  exit 1
fi
n=0
while [ "$(layers)" -gt 0 ] && [ $n -lt 4096 ]; do umount -l "$V/mnt" || break; n=$((n+1)); done
[ $n -gt 0 ] && echo "nova-mnt-private: cleared $n leftover layer(s) at $V/mnt"
mkdir -p "$V/mnt"
mount --bind "$V/mnt" "$V/mnt"
mount --make-private "$V/mnt"
echo "nova-mnt-private: $V/mnt is now a private bind"
