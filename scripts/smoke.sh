#!/usr/bin/env bash
# vctl 스모크 테스트 — 현재 Vault(VAULT_ADDR)에 실제 연결해 핵심 경로를 검증한다.
#
# 비파괴: 기존 ~/.vault-token 을 격리된 임시 HOME 의 vctl 캐시로 복사해 쓴다.
# (Vault 에 쓰기 작업 없음 — renew-self 는 자기 토큰 연장이라 안전.)
set -uo pipefail

VCTL_BIN="${VCTL_BIN:-bin/vctl}"
[ -x "$VCTL_BIN" ] || { echo "먼저 빌드: make build"; exit 1; }
VCTL_BIN="$(cd "$(dirname "$VCTL_BIN")" && pwd)/$(basename "$VCTL_BIN")"

REAL_HOME="$HOME"
TOKFILE="$REAL_HOME/.vault-token"
[ -f "$TOKFILE" ] || { echo "~/.vault-token 없음 — 'vault login' 먼저"; exit 1; }
TOKEN="$(tr -d '\r\n' < "$TOKFILE")"
export VAULT_ADDR="${VAULT_ADDR:-https://vault.sre.local}"

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/.vctl"
export HOME="$TMP"   # vctl StateDir = $TMP/.vctl (격리)
export VCTL_CONFIG="$TMP/.vctl/config.yaml" # 레포 로컬 설정과 분리

# 토큰 캐시 주입 헬퍼: $1=만료초 $2=renewable
inject() {
  python3 - "$TMP/.vctl/token" "$TOKEN" "$1" "$2" <<'PY'
import sys, json, datetime
path, tok, secs, renew = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4] == "true"
exp = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=secs)
json.dump({"token": tok, "expires": exp.isoformat(), "renewable": renew}, open(path, "w"))
PY
  chmod 600 "$TMP/.vctl/token"
}

P=0; F=0
ok(){ echo "  ✅ $*"; P=$((P+1)); }
no(){ echo "  ❌ $*"; F=$((F+1)); }

echo "════ vctl 스모크 ($VAULT_ADDR) ════"

echo "[1] --version"
V="$("$VCTL_BIN" --version </dev/null 2>&1)" && ok "$V" || no "version: $V"

echo "[2] status — 임베드 CA 로 TLS + ssh/config/ca 읽기 (DB는 graceful fail 예상)"
inject 28800 true
STATUS_OUT="$("$VCTL_BIN" status </dev/null 2>&1)"
echo "$STATUS_OUT" | sed 's/^/    /'
if echo "$STATUS_OUT" | grep -q "SSH CA" && echo "$STATUS_OUT" | grep -q "OK (ssh-"; then
  ok "Vault TLS + CA 읽기 성공 (임베드 CA 검증 통과)"
else
  no "CA 읽기 실패 — 임베드 CA 가 vault.sre.local 을 검증 못 했을 수 있음"
fi

echo "[3] token — 유효 캐시 재사용"
T="$("$VCTL_BIN" token </dev/null 2>/dev/null)"
[ "${T:0:6}" = "${TOKEN:0:6}" ] && ok "토큰 출력 (${T:0:14}...)" || no "token 불일치: ${T:0:14}"

echo "[4] token — renew 경로 (만료 30s + renewable → renew-self)"
inject 30 true
RT="$("$VCTL_BIN" token </dev/null 2>/tmp/vctl_renew.err)"
if [ -n "$RT" ]; then ok "renew-self 후 토큰 발급 (${RT:0:14}...)"; else no "renew 실패: $(cat /tmp/vctl_renew.err)"; fi

echo "[5] exec — 자식에 VAULT_TOKEN 주입"
inject 28800 true
INJ="$("$VCTL_BIN" exec -- sh -c 'echo $VAULT_TOKEN' </dev/null 2>/dev/null)"
[ "${INJ:0:6}" = "${TOKEN:0:6}" ] && ok "자식 env VAULT_TOKEN 확인 (${INJ:0:10}...)" || no "주입 실패: ${INJ:0:10}"

echo "[6] agent — 토큰 싱크 파일 기록 (3초 구동 후 SIGINT)"
inject 28800 true
"$VCTL_BIN" agent </dev/null >/tmp/vctl_agent.log 2>&1 &
AP=$!
for i in 1 2 3 4 5 6; do [ -s "$TMP/.vctl/token-sink" ] && break; sleep 0.5; done
if [ -s "$TMP/.vctl/token-sink" ] && [ "$(cut -c1-6 "$TMP/.vctl/token-sink")" = "${TOKEN:0:6}" ]; then
  ok "싱크 파일에 유효 토큰 기록됨"
else
  no "싱크 미기록"; cat /tmp/vctl_agent.log | sed 's/^/    /'
fi
kill -INT "$AP" 2>/dev/null; wait "$AP" 2>/dev/null

echo "════ 결과: PASS=$P FAIL=$F ════"
[ "$F" -eq 0 ]
