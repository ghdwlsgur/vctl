#!/usr/bin/env bash
# Stand up the local stack the integration tests need, or tear it down.
#
#   scripts/verify-stack.sh up      # start containers, print the env to export
#   scripts/verify-stack.sh env     # re-print the env for a running stack
#   scripts/verify-stack.sh down    # remove everything
#
# Why this exists: the integration tests assert real properties — that a policy
# reaches the token, that a role outside it is denied, that an untrusted CA is
# refused — and those assertions only mean something against a fixture that
# matches. Building it by hand drifts, and a drifted fixture fails the tests in
# ways that look like code regressions. The fixture belongs in version control
# next to the tests that depend on it.
#
# Nothing here is production-shaped: dev-mode Vault, a throwaway CA, a database
# with no data worth keeping. It listens on loopback only and is meant to be
# destroyed.
#
# Credentials are generated per run and written to $WORKDIR, never hardcoded.
# Not because a localhost dev password is worth protecting, but because this repo
# is public: a literal `password=...` reads as a secret to every scanner and
# every reviewer, and "it's only a test value" is exactly what a real leak claims
# too. Generating them costs one line and removes the question.
set -euo pipefail

PG=vctl-verify-pg
VAULT=vctl-verify-vault
SSHD=vctl-verify-sshd
PG_PORT=${PG_PORT:-55433}
VAULT_PORT=${VAULT_PORT:-58200}
SSHD_PORT=${SSHD_PORT:-52222}
PG_IMAGE=${PG_IMAGE:-postgres:18.3}
VAULT_IMAGE=${VAULT_IMAGE:-hashicorp/vault:1.21}
WORKDIR=${WORKDIR:-${TMPDIR:-/tmp}/vctl-verify}
CERTS="$WORKDIR/certs"
CREDS="$WORKDIR/creds.env"
TEST_USER=vctl-verify

# The certificate name vctl verifies against. It is deliberately not the dial
# host: that mismatch is the port-forward case serverName exists for, and the
# tests assert it is enforced rather than waved through.
TLS_SERVER_NAME=vctl-postgres.test

# mint_creds generates this run's throwaway credentials, or reloads the ones a
# previous `up` generated so `env` and `down` see the same values.
mint_creds() {
  if [ -f "$CREDS" ]; then
    # shellcheck disable=SC1090
    . "$CREDS"
    return
  fi
  mkdir -p "$WORKDIR"
  {
    echo "PG_PASSWORD=$(openssl rand -hex 16)"
    echo "VAULT_ROOT_TOKEN=$(openssl rand -hex 16)"
    echo "USERPASS_PASSWORD=$(openssl rand -hex 16)"
  } > "$CREDS"
  chmod 600 "$CREDS"
  # shellcheck disable=SC1090
  . "$CREDS"
}

v() { docker exec -i -e VAULT_ADDR=http://127.0.0.1:8200 -e VAULT_TOKEN="$VAULT_ROOT_TOKEN" "$VAULT" vault "$@"; }

wait_for_pg() {
  for _ in $(seq 1 60); do
    docker exec "$PG" pg_isready -U postgres -q 2>/dev/null && return 0
    sleep 1
  done
  echo "postgres did not become ready" >&2
  exit 1
}

make_certs() {
  rm -rf "$CERTS"; mkdir -p "$CERTS"
  openssl req -x509 -newkey rsa:2048 -sha256 -days 7 -nodes \
    -keyout "$CERTS/ca.key" -out "$CERTS/ca.crt" \
    -subj "/CN=vctl-verify-root-ca" -addext "basicConstraints=critical,CA:TRUE" 2>/dev/null
  openssl req -newkey rsa:2048 -nodes -keyout "$CERTS/server.key" -out "$CERTS/server.csr" \
    -subj "/CN=$TLS_SERVER_NAME" 2>/dev/null
  printf 'subjectAltName=DNS:%s,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n' "$TLS_SERVER_NAME" > "$CERTS/san.ext"
  openssl x509 -req -in "$CERTS/server.csr" -CA "$CERTS/ca.crt" -CAkey "$CERTS/ca.key" \
    -CAcreateserial -out "$CERTS/server.crt" -days 7 -sha256 -extfile "$CERTS/san.ext" 2>/dev/null
  # An unrelated CA for the negative TLS test: valid, but it signed nothing here.
  openssl req -x509 -newkey rsa:2048 -sha256 -days 7 -nodes \
    -keyout "$CERTS/other.key" -out "$CERTS/other.crt" -subj "/CN=unrelated-ca" 2>/dev/null
}

start_postgres() {
  docker rm -f "$PG" >/dev/null 2>&1 || true
  docker run -d --name "$PG" -e POSTGRES_PASSWORD="$PG_PASSWORD" -e POSTGRES_DB=vctl \
    -p "127.0.0.1:$PG_PORT:5432" "$PG_IMAGE" >/dev/null
  wait_for_pg
  local pgdata
  pgdata=$(docker exec -i "$PG" psql -U postgres -tAc "SHOW data_directory;")
  docker cp "$CERTS/server.crt" "$PG:$pgdata/server.crt"
  docker cp "$CERTS/server.key" "$PG:$pgdata/server.key"
  docker exec -u root "$PG" chown postgres:postgres "$pgdata/server.crt" "$pgdata/server.key"
  docker exec -u root "$PG" chmod 600 "$pgdata/server.key"
  docker exec -u root "$PG" chmod 644 "$pgdata/server.crt"
  docker exec -i "$PG" psql -U postgres -q -c "ALTER SYSTEM SET ssl = on;"
  docker restart "$PG" >/dev/null
  wait_for_pg

  # GRANT ... ON ALL TABLES in a Vault creation statement only covers tables that
  # exist when the credential is issued, and the schema is migrated later by the
  # tests themselves. Default privileges close that gap so a role minted before
  # the migration can still read what the migration creates. Production solves
  # the same problem properly with group roles (vault-iac postgres-groups.sh);
  # this is the throwaway equivalent.
  docker exec -i "$PG" psql -U postgres -d vctl -q \
    -c "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO PUBLIC;" \
    -c "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO PUBLIC;"
}

start_vault() {
  docker rm -f "$VAULT" >/dev/null 2>&1 || true
  docker run -d --name "$VAULT" -e VAULT_DEV_ROOT_TOKEN_ID="$VAULT_ROOT_TOKEN" \
    -e VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200 -p "127.0.0.1:$VAULT_PORT:8200" "$VAULT_IMAGE" >/dev/null
  for _ in $(seq 1 30); do v status >/dev/null 2>&1 && break; sleep 1; done
}

configure_vault() {
  local pgip
  pgip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$PG")

  v secrets enable -path=ssh ssh >/dev/null
  v write ssh/config/ca generate_signing_key=true >/dev/null
  # allowed_extensions must cover what vctl requests; without permit-pty the
  # signing call fails with "extensions are not on allowed list".
  v write ssh/roles/sre-core - >/dev/null <<'JSON'
{"key_type":"ca","algorithm_signer":"rsa-sha2-256","allow_user_certificates":true,
 "allowed_users":"*","allowed_extensions":"permit-pty,permit-agent-forwarding,permit-port-forwarding",
 "default_extensions":{"permit-pty":""},"ttl":"30m","max_ttl":"1h"}
JSON

  v secrets enable database >/dev/null
  v write database/config/vctl plugin_name=postgresql-database-plugin \
    allowed_roles='vctl-ro,vctl-rw,vctl-audit-writer,vctl-identity,vctl-status' \
    connection_url="postgresql://{{username}}:{{password}}@${pgip}:5432/vctl?sslmode=disable" \
    username=postgres password="$PG_PASSWORD" >/dev/null
  for role in vctl-ro vctl-rw vctl-audit-writer vctl-identity vctl-status; do
    v write "database/roles/$role" db_name=vctl default_ttl=1h max_ttl=4h \
      creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT ALL ON ALL TABLES IN SCHEMA public TO \"{{name}}\"; GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO \"{{name}}\";" >/dev/null
  done

  # KV fixture for `vctl kv`. Secrets the test identity may read under
  # kv/teams/test, and one under kv/teams/private that it may not — the denied
  # folder is what proves a search reports a 403 instead of stopping at it.
  # beta is both a secret and a folder, the shape KV allows and the real mount
  # has. No credentials here: the values are labels, and this repo is public.
  v secrets enable -path=kv -version=2 kv >/dev/null
  v kv put kv/teams/test/alpha username=alpha-user note=fixture >/dev/null
  v kv metadata put -custom-metadata=owner=fixture kv/teams/test/alpha >/dev/null
  v kv put kv/teams/test/beta username=beta-user >/dev/null
  v kv put kv/teams/test/beta/nested username=nested-user >/dev/null
  v kv put kv/teams/private/gamma username=gamma-user >/dev/null

  # vctl-user must NOT reach vctl-rw. TestDBCredsDeniedWithoutPolicy asserts the
  # least-privilege boundary between read and write roles, and folding rw in
  # here would make that test pass for the wrong reason — or fail, loudly, as it
  # did when this fixture was assembled by hand.
  #
  # The KV lines grant list on the two folders above the team's (Vault checks a
  # LIST against the path with a trailing slash, so these are exact, not globs —
  # a glob on kv/metadata/teams/* would let the private folder through) and
  # read+list under kv/teams/test only. kv/teams/private gets nothing, on
  # purpose: TestKVDeniedOutsidePolicy and the search walk depend on the 403.
  v policy write vctl-user - >/dev/null <<'HCL'
path "auth/token/lookup-self" { capabilities = ["read"] }
path "auth/token/renew-self"  { capabilities = ["update"] }
path "database/creds/vctl-ro"       { capabilities = ["read"] }
path "database/creds/vctl-identity" { capabilities = ["read"] }
path "database/creds/vctl-status"   { capabilities = ["read"] }
path "ssh/config/ca" { capabilities = ["read"] }
path "kv/metadata/"             { capabilities = ["list"] }
path "kv/metadata/teams/"       { capabilities = ["list"] }
path "kv/metadata/teams/test/*" { capabilities = ["read", "list"] }
path "kv/data/teams/test/*"     { capabilities = ["read"] }
HCL
  v policy write vctl-ssh - >/dev/null <<'HCL'
path "ssh/sign/sre-core" { capabilities = ["update"] }
path "database/creds/vctl-audit-writer" { capabilities = ["read"] }
HCL

  v auth enable userpass >/dev/null
  v write "auth/userpass/users/$TEST_USER" password="$USERPASS_PASSWORD" \
    policies=vctl-user,vctl-ssh token_ttl=1h token_max_ttl=4h >/dev/null

  v auth enable approle >/dev/null
  v write auth/approle/role/vctl-user token_policies=vctl-user,vctl-ssh token_ttl=1h token_max_ttl=4h >/dev/null
  v read -field=role_id auth/approle/role/vctl-user/role-id > "$WORKDIR/role-id"
  v write -f -field=secret_id auth/approle/role/vctl-user/secret-id > "$WORKDIR/secret-id"

  v read -field=public_key ssh/config/ca > "$WORKDIR/vault_ca.pub"
}

start_sshd() {
  local dir="$WORKDIR/sshd"
  rm -rf "$dir"; mkdir -p "$dir"
  cp "$WORKDIR/vault_ca.pub" "$dir/vault_ca.pub"
  # adduser -D leaves the account locked, and sshd refuses a locked account even
  # for public-key auth ("User ... not allowed because account is locked"), so
  # the shadow entry is opened up explicitly.
  cat > "$dir/Dockerfile" <<'DOCKER'
FROM alpine:3.20
RUN apk add --no-cache openssh-server \
 && ssh-keygen -A \
 && adduser -D -s /bin/sh ubuntu \
 && sed -i 's/^ubuntu:!/ubuntu:*/' /etc/shadow
COPY vault_ca.pub /etc/ssh/vault_ca.pub
RUN printf '%s\n' \
    'TrustedUserCAKeys /etc/ssh/vault_ca.pub' \
    'PubkeyAuthentication yes' \
    'PasswordAuthentication no' \
    'PermitRootLogin no' \
    'AuthorizedKeysFile none' \
    > /etc/ssh/sshd_config.d/vault-ca.conf
EXPOSE 22
CMD ["/usr/sbin/sshd","-D","-e"]
DOCKER
  docker rm -f "$SSHD" >/dev/null 2>&1 || true
  docker build -q -t "$SSHD" "$dir" >/dev/null
  docker run -d --name "$SSHD" -p "127.0.0.1:$SSHD_PORT:22" "$SSHD" >/dev/null
}

print_env() {
  local user pass
  read -r user pass <<<"$(v read -format=json database/creds/vctl-rw \
    | python3 -c 'import json,sys; d=json.load(sys.stdin)["data"]; print(d["username"], d["password"])')"
  cat <<ENV
# eval "\$(scripts/verify-stack.sh env)"
export VCTL_TEST_DSN='postgres://postgres:$PG_PASSWORD@127.0.0.1:$PG_PORT/vctl?sslmode=disable'
export VCTL_TEST_VAULT_ADDR='http://127.0.0.1:$VAULT_PORT'
export VCTL_TEST_VAULT_USER='$TEST_USER'
export VCTL_TEST_VAULT_PASS='$USERPASS_PASSWORD'
export VCTL_TEST_TLS_HOST='127.0.0.1'
export VCTL_TEST_TLS_PORT='$PG_PORT'
export VCTL_TEST_TLS_SERVER='$TLS_SERVER_NAME'
export VCTL_TEST_TLS_CA='$CERTS/ca.crt'
export VCTL_TEST_TLS_USER='$user'
export VCTL_TEST_TLS_PASS='$pass'
ENV
}

case "${1:-up}" in
  up)
    mkdir -p "$WORKDIR"
    rm -f "$CREDS"          # a fresh stack gets fresh credentials
    mint_creds
    make_certs
    start_postgres
    start_vault
    configure_vault
    start_sshd
    echo "stack up (postgres :$PG_PORT tls, vault :$VAULT_PORT, sshd :$SSHD_PORT)" >&2
    echo "workdir: $WORKDIR" >&2
    print_env
    ;;
  env) mint_creds; print_env ;;
  down)
    docker rm -f "$PG" "$VAULT" "$SSHD" >/dev/null 2>&1 || true
    rm -f "$CREDS"
    echo "stack removed" >&2
    ;;
  *)
    echo "usage: $0 {up|env|down}" >&2
    exit 2
    ;;
esac
