#!/usr/bin/env bash
# Collapse kolla's stacked /var/lib/nova/mnt layers on a docker compute host
# without touching nova_libvirt (the running VMs). Run by
# kolla-nova-mount-propagation.yml when -e nova_mnt_collapse=true.
#
# Why the layers exist: see the playbook header. Validated on ten SRE compute
# hosts on 2026-10-19 (1023 layers on the worst) with every VM left running.
#
#   1. umount -l every share under /var/lib/nova/mnt  (open VM fds keep working)
#   2. umount /var/lib/nova/mnt once on the host       (containers keep 1 bind each)
#   3. remount each share once on the host, with the options it had
#      (propagates to nova_compute, nova_libvirt and nova_ssh)
#
# Stops, and puts the shares back, if any container would lose its bind:
# re-binding it means restarting nova_libvirt, which takes the VMs with it.
set -u
D=/var/lib/nova/mnt
# The volume lives under docker's data root, which is not always /var/lib/docker
# (sre-srv-0047 keeps it in /home/docker).
V=$(docker info -f '{{.DockerRootDir}}' 2>/dev/null)/volumes/nova_compute/_data
STATE=/root/nova-mnt-fix.$(date +%Y%m%d%H%M%S).shares
[ -d "$V" ] || { echo "STOP: nova_compute volume not found at $V"; exit 2; }
echo "nova_compute volume: $V"

cpid() { docker inspect -f '{{.State.Pid}}' "$1"; }
cnt() { awk -v p="$2" '$5==p' "/proc/$1/mountinfo" | wc -l; }
layers() { echo "[$1] layers host=$(cnt self $D) compute=$(cnt "$(cpid nova_compute)" $D) libvirt=$(cnt "$(cpid nova_libvirt)" $D) ssh=$(cnt "$(cpid nova_ssh)" $D)"; }
vms() {
  local e=0 d r
  for d in $(docker exec nova_libvirt virsh list --name); do
    r=$(docker exec nova_libvirt virsh domblkerror "$d" | grep -v '^\s*$')
    [ "$r" = "No errors found" ] || { e=$((e+1)); echo "  ERR $d: $r"; }
  done
  echo "[$1] vms running=$(docker exec nova_libvirt virsh list --name | grep -c .) disk-errors=$e"
}
files() { docker exec -u root "$1" sh -c "ls '$2' 2>/dev/null | wc -l"; }

# One line per share: mountpoint fstype source options-to-reuse.
# Only options mount.nfs accepts; namlen, addr, clientaddr, local_lock are
# negotiated or derived and are left to the kernel.
awk -v d="$D/" 'index($5,d)==1 && substr($5,length(d)+1) !~ /\// {
  for(i=7;i<=NF;i++) if($i=="-"){
    n=split($(i+3),o,","); keep="";
    for(k=1;k<=n;k++) if(o[k] ~ /^(vers|rsize|wsize|proto|timeo|retrans|sec|port)=/ || o[k] ~ /^(hard|soft|ro|rw)$/) keep=keep (keep==""?"":",") o[k];
    print $5, $(i+1), $(i+2), keep; break } }' /proc/self/mountinfo | sort -u > "$STATE"

layers before; vms before
echo "[before] shares (saved to $STATE):"; sed 's/^/  /' "$STATE"
declare -A BEFORE
while read -r mp fs src opts; do BEFORE[$mp]=$(files nova_libvirt "$mp"); echo "  $mp: libvirt sees ${BEFORE[$mp]} entries"; done < "$STATE"

if [ "$(cnt "$(cpid nova_libvirt)" $D)" -lt 2 ]; then echo "SKIP collapse: libvirt is not stacked"; else
  echo "== 1. umount -l each share"
  while read -r mp fs src opts; do umount -l "$mp" || { echo "STOP: umount -l $mp failed"; exit 4; }; done < "$STATE"
  layers step1

  echo "== 2. umount $D once (host)"
  if ! umount "$D"; then
    echo "STOP: step 2 failed; putting the shares back"
    while read -r mp fs src opts; do mount -t "$fs" -o "$opts" "$src" "$mp"; done < "$STATE"; layers restored; exit 5
  fi
  layers step2
  for c in nova_compute nova_libvirt nova_ssh; do
    if [ "$(cnt "$(cpid $c)" $D)" -lt 1 ]; then
      echo "STOP: $c lost its $D bind; remounting on the host and stopping"
      while read -r mp fs src opts; do mkdir -p "$mp"; mount -t "$fs" -o "$opts" "$src" "$mp"; done < "$STATE"; layers after-stop; vms after-stop; exit 6
    fi
  done

  echo "== 3. remount each share once (host)"
  while read -r mp fs src opts; do
    mkdir -p "$mp"
    mount -t "$fs" -o "$opts" "$src" "$mp" || { echo "STOP: mount $src on $mp failed"; exit 7; }
  done < "$STATE"
  sleep 2
  layers step3
fi

echo "== check: every share visible again with the same entries"
bad=0
while read -r mp fs src opts; do
  copies="host=$(cnt self "$mp") libvirt=$(cnt "$(cpid nova_libvirt)" "$mp")"
  now=$(files nova_libvirt "$mp")
  echo "  $mp: $copies libvirt sees $now (before ${BEFORE[$mp]})"
  [ "$now" = "${BEFORE[$mp]}" ] || bad=1
done < "$STATE"
vms after-collapse
[ "$bad" -eq 0 ] || { echo "STOP: a share does not show what it showed before"; exit 8; }
echo "== total host mounts: $(wc -l < /proc/self/mountinfo)"
