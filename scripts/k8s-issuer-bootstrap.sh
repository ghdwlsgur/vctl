#!/usr/bin/env bash
# Give Vault's Kubernetes secrets engine a foothold in one cluster and leave
# what vault-iac needs in Vault KV.
#
#   scripts/k8s-issuer-bootstrap.sh <kubectl-context> <cluster-name> [--host https://api:6443]
#
# Applies deploy/k8s/vault-issuer.yaml with the context, waits for the issuer's
# token, and writes host / ca / jwt to kv/teams/sre/k8s/<cluster-name>/issuer
# with `vctl kv set` (values via temp files, nothing on the command line).
# --host overrides the API address Vault should dial — for a cluster Vault
# reaches by a different route than your kubeconfig does (its own cluster:
# https://kubernetes.default.svc).
set -euo pipefail
CTX="${1:?kubectl context}"; NAME="${2:?cluster name}"; shift 2
HOST=""
while [ $# -gt 0 ]; do case "$1" in --host) HOST="$2"; shift 2;; *) echo "unknown arg $1" >&2; exit 2;; esac; done
HERE="$(cd "$(dirname "$0")/.." && pwd)"
KV="kv/teams/sre/k8s/${NAME}/issuer"

echo "== apply issuer manifest to ${CTX}"
kubectl --context "$CTX" apply -f "$HERE/deploy/k8s/vault-issuer.yaml"
echo "== wait for the issuer token"
for i in $(seq 1 30); do
  TOK=$(kubectl --context "$CTX" -n vctl-access get secret vault-issuer-token -o jsonpath='{.data.token}' 2>/dev/null || true)
  [ -n "$TOK" ] && break; sleep 1
done
[ -n "$TOK" ] || { echo "no token on secret vault-issuer-token after 30s" >&2; exit 1; }
[ -n "$HOST" ] || HOST=$(kubectl --context "$CTX" config view --minify -o jsonpath='{.clusters[0].cluster.server}')

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT; chmod 700 "$TMP"
printf '%s' "$TOK" | base64 -d > "$TMP/jwt"
kubectl --context "$CTX" -n vctl-access get secret vault-issuer-token -o jsonpath='{.data.ca\.crt}' | base64 -d > "$TMP/ca"
echo "== store issuer credentials at ${KV}"
vctl kv set "$KV" host="$HOST" ca=@"$TMP/ca" jwt=@"$TMP/jwt"
cat <<MSG

done. next, in vault-iac: add "${NAME}" to the k8s clusters list (modules/vctl/k8s.tf)
so Jenkins mounts kubernetes/${NAME} with roles viewer/editor/admin, then:

  vctl k8s cluster set ${NAME} --from-context ${CTX} --source vault:kubernetes/${NAME}
  vctl k8s use ${NAME} && kubectl get nodes
MSG
