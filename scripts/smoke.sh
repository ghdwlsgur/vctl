#!/usr/bin/env bash
# Smoke test against the current Vault endpoint.
#
# Non-destructive: copies the existing ~/.vault-token into an isolated temporary
# HOME and uses vctl's cache there. renew-self only renews the caller's token.
set -uo pipefail

VCTL_BIN="${VCTL_BIN:-bin/vctl}"
[ -x "$VCTL_BIN" ] || { echo "Build first: make build"; exit 1; }
VCTL_BIN="$(cd "$(dirname "$VCTL_BIN")" && pwd)/$(basename "$VCTL_BIN")"

REAL_HOME="$HOME"
TOKFILE="$REAL_HOME/.vault-token"
[ -f "$TOKFILE" ] || { echo "Missing ~/.vault-token. Run vault login first."; exit 1; }
TOKEN="$(tr -d '\r\n' < "$TOKFILE")"
export VAULT_ADDR="${VAULT_ADDR:-https://vault.sre.local}"

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/.vctl"
export HOME="$TMP"
export VCTL_CONFIG="$TMP/.vctl/config.yaml"

inject() {
  python3 - "$TMP/.vctl/token" "$TOKEN" "$1" "$2" <<'PY'
import sys, json, datetime
path, tok, secs, renew = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4] == "true"
exp = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=secs)
json.dump({"token": tok, "expires": exp.isoformat(), "renewable": renew}, open(path, "w"))
PY
  chmod 600 "$TMP/.vctl/token"
}

P=0
F=0
ok(){ echo "  PASS $*"; P=$((P+1)); }
no(){ echo "  FAIL $*"; F=$((F+1)); }
indent() {
  local text="${1//$'\n'/$'\n'    }"
  printf '    %s\n' "$text"
}

echo "==== vctl smoke ($VAULT_ADDR) ===="

echo "[1] --version"
if V="$("$VCTL_BIN" --version </dev/null 2>&1)"; then
  ok "$V"
else
  no "version: $V"
fi

echo "[2] status: embedded CA, Vault TLS, SSH CA read"
inject 28800 true
STATUS_OUT="$("$VCTL_BIN" status </dev/null 2>&1)"
indent "$STATUS_OUT"
if echo "$STATUS_OUT" | grep -q "SSH CA" && echo "$STATUS_OUT" | grep -q "OK (ssh-"; then
  ok "Vault TLS and CA read succeeded"
else
  no "CA read failed. The embedded CA may not validate vault.sre.local."
fi

echo "[3] token: reuse valid cache"
T="$("$VCTL_BIN" token </dev/null 2>/dev/null)"
if [ "${T:0:6}" = "${TOKEN:0:6}" ]; then
  ok "token output (${T:0:14}...)"
else
  no "token mismatch: ${T:0:14}"
fi

echo "[4] token: renew path"
inject 30 true
RT="$("$VCTL_BIN" token </dev/null 2>/tmp/vctl_renew.err)"
if [ -n "$RT" ]; then
  ok "renew-self returned token (${RT:0:14}...)"
else
  RENEW_ERR="$(< /tmp/vctl_renew.err)"
  no "renew failed: $RENEW_ERR"
fi

echo "[5] exec: inject VAULT_TOKEN into child"
inject 28800 true
# shellcheck disable=SC2016
INJ="$("$VCTL_BIN" exec -- sh -c 'printf "%s\n" "$VAULT_TOKEN"' </dev/null 2>/dev/null)"
if [ "${INJ:0:6}" = "${TOKEN:0:6}" ]; then
  ok "child VAULT_TOKEN present (${INJ:0:10}...)"
else
  no "injection failed: ${INJ:0:10}"
fi

echo "[6] agent: write token sink"
inject 28800 true
"$VCTL_BIN" agent </dev/null >/tmp/vctl_agent.log 2>&1 &
AP=$!
for _ in 1 2 3 4 5 6; do
  [ -s "$TMP/.vctl/token-sink" ] && break
  sleep 0.5
done
if [ -s "$TMP/.vctl/token-sink" ] && [ "$(cut -c1-6 "$TMP/.vctl/token-sink")" = "${TOKEN:0:6}" ]; then
  ok "sink file contains the valid token"
else
  no "sink file was not written"
  AGENT_LOG="$(< /tmp/vctl_agent.log)"
  indent "$AGENT_LOG"
fi
kill -INT "$AP" 2>/dev/null
wait "$AP" 2>/dev/null

echo "==== result: PASS=$P FAIL=$F ===="
[ "$F" -eq 0 ]
