# vctl

**Vault Agent 없이** Vault 토큰을 "에이전트처럼" 직접 관리하는 CLI (+ SSH CA 서버 접속).

- 데몬 0 — `vctl` 바이너리가 로그인·**자동 갱신**·재인증·서명을 직접 수행
- 토큰 자동 유지 — 만료 전 `renew-self`, 갱신 불가 시 자동 재인증(approle)
- 다른 도구 연동 — `vctl token` / `vctl exec` / `vctl agent`(싱크 파일)로 기존 `vault` CLI·terraform 등에 토큰 공급
- 사설 CA 내장 — 별도 CA 설치 없이 Vault·Postgres TLS 검증
- 정적 키 없음 — 서버 접속마다 단명 인증서(TTL 30분) 발급
- 중앙 인벤토리(Postgres) — 호스트/IP/유저/점프를 한곳에서, 비밀은 0

## Vault Agent 처럼 쓰기 (데몬 없이)

```bash
# (A) 기존 vault CLI 에 토큰 공급 — 자동 갱신/재인증 포함
export VAULT_TOKEN=$(vctl token)
vault kv get kv/services/foo

# (B) 자식 프로세스에 주입 — 실행 동안 토큰 안 끊김
vctl exec -- terraform apply
vctl exec -- vault kv get kv/services/foo
#   주의: 자식 env 의 VAULT_TOKEN 은 시작 시점 값으로 고정된다(env 는 런타임 변경 불가).
#   renew-self 로 "같은 토큰"이 연장되는 동안은 유효하지만, max_ttl 을 넘겨
#   토큰이 교체되면 자식은 못 따라간다. 초장수명 작업은 (C) 싱크 파일 소비를 권장.

# (C) 상주 모드 — 토큰을 싱크 파일로 계속 갱신해 떨궈둠
vctl agent --sink /run/user/$(id -u)/vault-token
#   다른 셸/도구:  VAULT_TOKEN=$(cat ~/.vctl/token-sink) vault ...
```

무인 환경(CI 등)은 approle 자격을 주면 사람 개입 없이 재인증까지 자동:

```bash
export VCTL_ROLE_ID_FILE=/etc/vctl/role_id  VCTL_SECRET_ID_FILE=/etc/vctl/secret_id
vctl agent          # auto-auth → renew → 만료 시 approle 재인증, 무한 유지
```

### 동작 모델 (Vault Agent 대비)

| Vault Agent | vctl 대응 | 차이 |
|---|---|---|
| auto-auth | `login` / approle env | 데몬 대신 CLI 1회 또는 `agent` |
| token sink | `vctl agent --sink` | 동일 (파일에 토큰 기록) |
| auto-renew | 모든 명령에 내장 + `agent` | 만료 전 자동 `renew-self` |
| `agent exec` | `vctl exec --` | 자식 수명 동안 백그라운드 갱신 |
| caching proxy | (미지원) | 토큰 공급에 집중, 프록시는 범위 밖 |

## 신규 팀원 (3단계)

```bash
# 1. 설치
brew install ghdwlsgur/tap/vctl

# 2. 로그인 (유일한 설정)
vctl login

# 3. 접속 — 이름을 몰라도 됨
vctl ssh sre-srv-0047      # 정확히
vctl ssh 0047              # 일부만 (퍼지 매칭)
vctl ssh                   # 목록에서 고르기
vctl list                  # 뭐가 있는지 보기
```

설정 파일 없이도 기본값으로 동작한다. 레포별 설정은 `.vctl/config.yaml` 에 두고, `~/.vctl/` 는 토큰 캐시 용도로 자동 생성된다.

## 접속 흐름

```
vctl ssh <host>
  → Vault 로그인(캐시 토큰 재사용)
  → database/creds/vctl-ro  : 단명 PG자격 → 인벤토리 조회
  → ed25519 키 메모리 생성     : 디스크에 안 떨어짐
  → ssh/sign/sre-core         : 30분 cert 서명
  → 네이티브 SSH (점프 체인 + PTY)
```

## 명령

| 명령 | 설명 |
|---|---|
| `vctl login [--method userpass\|oidc\|approle]` | Vault 로그인, 토큰 캐시 |
| `vctl token` | 유효 토큰 출력 (자동 갱신/재인증) |
| `vctl exec -- <cmd>` | `VAULT_TOKEN`/`VAULT_ADDR` 주입해 자식 실행 (실행 동안 토큰 유지) |
| `vctl agent [--sink <path>]` | 상주 모드 — 자동 갱신 + 토큰 싱크 기록 |
| `vctl ssh [host]` | 접속 (정확/퍼지/피커) |
| `vctl list [--dc <dc>]` | 인벤토리 목록 |
| `vctl status` | 로그인·CA·DB 연결 점검 |
| `vctl sync [--migrate] [--prefix sre]` | `~/.ssh/config`+프로브로 인벤토리 갱신 (관리자) |
| `vctl logout` | 캐시 토큰 폐기 |

### 환경변수
`VAULT_ADDR`, `VCTL_AUTH_METHOD`, `VCTL_ROLE_ID(_FILE)`, `VCTL_SECRET_ID(_FILE)`, `VCTL_SINK`, `VCTL_DB_HOST`,
`VCTL_CA_ROLE`, `VCTL_SSH_DEFAULT_USER`, `VCTL_SYNC_PROBE_TIMEOUT`, `VCTL_SYNC_PROBE_CONCURRENCY` 등으로
baked-in 기본값을 덮어쓴다.

`.vctl/config.yaml` 예시:

```yaml
vault_addr: https://vault.sre.local
db_host: vctl-postgres.sre.local
ca_role: sre-core
ssh_default_user: ubuntu
sync_probe_timeout: 3s
sync_probe_concurrency: 32
dc_rules:
  - name: incheon
    prefixes: ["10.40.0.", "192.168.10."]
  - name: seoul-onprem
    prefixes: ["192.168.201.", "192.168.190.", "192.168.110."]
```

초기 설정은 샘플을 복사해서 시작한다:

```bash
mkdir -p .vctl
cp .vctl/config.example.yaml .vctl/config.yaml
```

## 관리자 부트스트랩 (1회)

```bash
# Vault DB 엔진·role·정책 구성
PG_ADMIN_PASS=<root비번> ./deploy/vault/setup.sh

# 팀원 계정 (v1 userpass)
vault write auth/userpass/users/<id> password=<once> policies=vctl-user

# 인벤토리 최초 적재 (vctl-admin 토큰으로)
vctl sync --migrate
```

OIDC SSO 전환(팀원당 계정 0): [`deploy/vault/oidc-phase2.md`](deploy/vault/oidc-phase2.md).

## 빌드

```bash
make build
```

## 릴리스

릴리스는 Git tag push 로 GoReleaser 가 수행한다. GitHub Release 아티팩트를 만들고,
Homebrew tap(`ghdwlsgur/homebrew-tap`)의 `Formula/vctl.rb`를 갱신한다.

필요한 저장소 secret:

```text
HOMEBREW_TAP_GITHUB_TOKEN
```

토큰에는 `ghdwlsgur/homebrew-tap`에 push 할 수 있는 권한이 필요하다.

```bash
git tag v0.1.0
git push origin v0.1.0
```

## 설계 메모

- **인벤토리 ⟂ 비밀**: DB 엔 토폴로지만. cert·DB자격은 모두 Vault 가 단명 발급. DB 가 털려도 새는 건 "서버가 있다"는 사실뿐.
- **로테이션 직교**: SSH CA 키 교체와 DB 자격 로테이션은 서로 안 엮인다. DB 가 추적하는 건 호스트별 `ca_key_version`(무중단 CA 교체 진행 상태)뿐.
- **설정 가능한 기본값**: `internal/config/config.go`의 `Defaults()` 는 온보딩용 기본값만 담는다. Vault/DB/CA role/SSH 기본 유저/동기화 probe/DC 분류는 env 또는 레포의 `.vctl/config.yaml` 로 덮어쓴다.

## 구조

```
cmd/vctl           진입점
internal/config      기본값 + 임베드 CA
internal/vaultc      Vault: 로그인(userpass/oidc)·서명·DB자격·CA
internal/store       Postgres 인벤토리 (verify-full TLS)
internal/sshc        네이티브 SSH: cert signer·점프 체인·PTY
internal/syncx       ssh config 파싱 + 프로브
internal/cli         cobra 명령
deploy/vault         정책·DB엔진 부트스트랩·OIDC 가이드
```
