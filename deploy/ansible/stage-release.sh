#!/usr/bin/env bash
# Stage a released vctl-agent binary into files/ for the fleet playbook, and
# print the -e argument the playbook needs.
#
#   ./stage-release.sh v0.3.3
#   ansible-playbook site.yml -e vctl_bin_sha256=<printed value>
#
# WHY a script: the manual sequence (gh release download → verify against
# checksums.txt → extract → copy → hash) was repeated by hand for three
# consecutive releases in one day. Every step is mechanical and the one thing
# a human adds is the chance of passing a stale or mistyped sha to the fleet —
# which the role would then reject on 49 hosts, or worse, accept if the typo
# happens to match the wrong staging file.
#
# The archive is verified against the release's checksums.txt BEFORE the binary
# leaves it, and the printed sha is computed from the staged file itself — the
# same file the role will checksum on every host.
set -euo pipefail

ver="${1:?usage: stage-release.sh vX.Y.Z}"
repo="ghdwlsgur/vctl"
here="$(cd "$(dirname "$0")" && pwd)"

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$@"
  else
    shasum -a 256 "$@"
  fi
}

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

gh release download "$ver" -R "$repo" \
  -p 'vctl-agent_*_linux_amd64.tar.gz' -p checksums.txt -D "$tmp"

archive="vctl-agent_${ver#v}_linux_amd64.tar.gz"
(cd "$tmp" && grep " ${archive}\$" checksums.txt | sha256 -c -)

tar -xzf "$tmp/$archive" -C "$tmp" vctl-agent
install -m 0755 "$tmp/vctl-agent" "$here/files/vctl-agent"

sha="$(sha256 "$here/files/vctl-agent" | cut -d' ' -f1)"
echo "staged: files/vctl-agent ($ver)"
echo "-e vctl_bin_sha256=$sha"
