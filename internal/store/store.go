// Package store manages the central Postgres inventory. It stores no secrets.
//
// Connections use short-lived Vault-issued credentials and verify-full TLS
// with the embedded private CA.
package store

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// CredsFunc returns fresh database credentials. It is invoked before every new
// physical connection (including the first), so a long-running pool survives
// the short TTL of Vault dynamic credentials without a Vault Agent: connections
// are recycled before their lease expires and re-fetch live credentials here.
type CredsFunc func(context.Context) (user, pass string, err error)

type Server struct {
	Hostname     string
	IP           string
	Port         int
	User         string
	JumpVia      string // empty means no jump host
	DC           string
	CARole       string
	CAKeyVersion int
	LastSeenUp   *time.Time
	ExtraIPs     []string // additional addresses the host answers on (VIPs, extra NICs)

	// State is what an operator declared about this host — see StateActive and
	// friends. It is not observed and never inferred: liveness answers "is there
	// a signal", this answers "is that expected". Empty means active, so rows
	// written before the column existed and snapshots taken by an older binary
	// read as active rather than as an unknown fourth thing.
	State string
}

// Operator-declared host states. The database constrains the column to exactly
// these, so adding one is a migration — every renderer and alert rule that
// switches on the value has to learn the new word first.
const (
	// StateActive is the default: the host is expected to be reachable, so a
	// liveness of "down" on it is a problem rather than a record.
	StateActive = "active"
	// StateMaintenance is a planned window. Down is expected and temporary.
	StateMaintenance = "maintenance"
	// StateBroken is a fault somebody diagnosed. Observation cannot tell a dead
	// NIC from a host nobody installed the agent on; this is where that
	// judgement is recorded.
	StateBroken = "broken"
	// StateRetired is decommissioned but deliberately kept in the inventory,
	// e.g. so its audit history stays easy to find.
	StateRetired = "retired"
)

// HostStates is the accepted set, in escalating order of "do not expect this
// host to answer". Order is the listing's, not the database's.
var HostStates = []string{StateActive, StateMaintenance, StateBroken, StateRetired}

// StateOrActive normalises the empty string to active. Reading it through this
// keeps the "empty means active" rule in one place instead of at every caller
// that renders or compares a state.
func StateOrActive(s string) string {
	if s == "" {
		return StateActive
	}
	return s
}

// ValidState reports whether s is a state the database would accept.
func ValidState(s string) bool { return slices.Contains(HostStates, s) }

type Store struct {
	pool *pgxpool.Pool
}

// Workload describes the concurrency a caller can actually use. Long-running
// heartbeat/collector loops are serial and must not reserve the same pool fanout
// as interactive commands that issue independent queries.
type Workload int

const (
	WorkloadInteractive Workload = iota
	WorkloadSerial
)

// Pool tuning is bounded by two facts outside this package, both recorded here
// so the test can enforce them.
const (
	// credentialTTL is the TTL Vault's database engine issues these credentials
	// with (`default_ttl` on the vctl DB roles). A connection outliving its lease
	// is not slow, it is broken: the role is gone from Postgres.
	credentialTTL = time.Hour

	// maxDaemonInterval is the longest heartbeat any long-running vctl daemon
	// uses between database writes (node-agent's --interval default is the
	// largest at 5m). An idle timeout at or under this is a reaper racing the
	// next write.
	maxDaemonInterval = 5 * time.Minute
)

// tunePool sets the pool's connection recycling policy.
//
// Recycling exists because Vault dynamic credentials expire. Connections are
// dropped inside the lease window so each physical connection re-fetches a live
// credential via BeforeConnect, which is what lets the collector and watch
// daemons run for days without a restart.
//
// But every recycle costs a Vault issuance plus a CREATE ROLE / DROP ROLE pair
// in Postgres, so the lease window is a budget, not free headroom. Measured on
// the fleet with a 30m lifetime and a 5m idle timeout: 42 agents produced 114
// dynamic roles per hour — 2.7 each — to write one row every five minutes.
//
// The idle timeout was the more wasteful of the two. At 5m it exactly equalled
// node-agent's interval, so a connection became collectable at the moment it was
// next needed and the reaper and the heartbeat raced. Losing that race pays a
// full Vault round trip to replace a connection that was about to be used.
//
// It is split out from Open so the invariants below are testable without a
// database; Open cannot run without one.
// MaxConnAge reports the oldest a pooled connection can get.
//
// Credential holders need this: a connection opened right now may still be in
// the pool this long from now, so any credential handed to it must outlive the
// value returned here. Deriving that floor from the pool is the point — the two
// numbers have to move together, and a hand-picked constant elsewhere would not.
func MaxConnAge() time.Duration {
	cfg, err := pgxpool.ParseConfig("postgres://localhost:5432/postgres")
	if err != nil {
		// Unreachable: the DSN is a literal. Fall back to the configured values
		// rather than panic in a getter.
		return 50 * time.Minute
	}
	tunePool(cfg)
	return cfg.MaxConnLifetime + cfg.MaxConnLifetimeJitter
}

func tunePool(cfg *pgxpool.Config) {
	tunePoolFor(cfg, WorkloadInteractive)
}

func tunePoolFor(cfg *pgxpool.Config, workload Workload) {
	cfg.MaxConns = 4
	if workload == WorkloadSerial {
		cfg.MaxConns = 1
	}
	// Recycling a connection no longer implies issuing a credential — see
	// internal/dbcreds — so the lifetime is set for connection hygiene rather
	// than pushed as close to the lease as it will safely go. Staying well
	// under the TTL is what buys the credential holder a wide window in which
	// it may hand the cached credential out: with 25m of worst-case connection
	// age against a 1h lease, a credential is reusable for over half its life
	// even if renewal is unavailable.
	//
	// Jitter is added to the deadline (pgx: now+lifetime+jitter), not
	// subtracted, so it counts toward the age a credential must cover.
	cfg.MaxConnLifetime = 20 * time.Minute
	cfg.MaxConnLifetimeJitter = 5 * time.Minute
	cfg.MaxConnIdleTime = 10 * time.Minute
}

// Open creates a Postgres pool with short-lived credentials and caPEM TLS roots.
// serverName overrides the TLS SNI/verification name; when empty it defaults to host.
// Use serverName when dialing through a port-forward/proxy where the dial host
// (e.g. 127.0.0.1) differs from the certificate's DNS name.
func Open(ctx context.Context, host string, port int, dbname string, getCreds CredsFunc, serverName string, caPEM []byte) (*Store, error) {
	return OpenFor(ctx, host, port, dbname, getCreds, serverName, caPEM, WorkloadInteractive)
}

// OpenFor opens the inventory using a pool sized for the caller's real
// concurrency. WorkloadSerial keeps each fleet daemon at one DB connection.
func OpenFor(ctx context.Context, host string, port int, dbname string, getCreds CredsFunc, serverName string, caPEM []byte, workload Workload) (*Store, error) {
	// No userinfo in the DSN: credentials are injected per-connection by
	// BeforeConnect so the pool can refresh them as dynamic leases roll over.
	//
	// sslmode is explicit and must stay that way. Without it pgx parses the DSN
	// under libpq's default of "prefer", which builds a plaintext entry in
	// ConnConfig.Fallbacks — and assigning TLSConfig below only touches the
	// primary. The result was a connection that downgraded to cleartext exactly
	// when verification failed, i.e. against the attacker the verification is
	// there to stop, while pg_stat_ssl reported ssl=false and nothing surfaced.
	dsn := fmt.Sprintf("postgres://%s:%d/%s?sslmode=verify-full", host, port, dbname)

	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse dsn: %w", err)
	}
	pool := x509.NewCertPool()
	if len(caPEM) > 0 && !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("parse embedded CA")
	}
	if serverName == "" {
		serverName = host
	}
	cfg.ConnConfig.TLSConfig = &tls.Config{
		RootCAs:    pool,
		ServerName: serverName,
		MinVersion: tls.VersionTLS12,
	}
	// Belt and braces: whatever a future pgx decides "verify-full" implies, a
	// fallback is a second connection attempt this function never configured and
	// therefore cannot vouch for. There is exactly one way to reach the inventory
	// database, and it is the verified one above.
	cfg.ConnConfig.Fallbacks = nil
	tunePoolFor(cfg, workload)
	cfg.BeforeConnect = func(ctx context.Context, cc *pgx.ConnConfig) error {
		user, pass, err := getCreds(ctx)
		if err != nil {
			return fmt.Errorf("fetch db creds: %w", err)
		}
		cc.User = user
		cc.Password = pass
		return nil
	}

	p, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("postgres connect: %w", err)
	}
	if err := p.Ping(ctx); err != nil {
		p.Close()
		return nil, fmt.Errorf("postgres ping: %w", err)
	}
	return &Store{pool: p}, nil
}

// OpenLocal opens a static-credential Postgres DSN for local development and
// recovery testing. It deliberately accepts loopback hosts only: production
// connections must continue through Vault-issued credentials and verified TLS.
func OpenLocal(ctx context.Context, dsn string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse local dsn: %w", err)
	}
	// pgx expands a comma-separated host list into Fallbacks and dials them in
	// order when the primary refuses. Checking ConnConfig.Host alone would let
	// "127.0.0.1,db.example.com" satisfy the guard and still reach production on
	// the second attempt, so every host pgx may dial has to clear it.
	hosts := []string{cfg.ConnConfig.Host}
	for _, fb := range cfg.ConnConfig.Fallbacks {
		hosts = append(hosts, fb.Host)
	}
	for _, host := range hosts {
		if !isLoopbackHost(host) {
			return nil, fmt.Errorf("local dsn host must be loopback, got %q", host)
		}
	}
	cfg.MaxConns = 4
	p, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("local postgres connect: %w", err)
	}
	if err := p.Ping(ctx); err != nil {
		p.Close()
		return nil, fmt.Errorf("local postgres ping: %w", err)
	}
	return &Store{pool: p}, nil
}

// DSNEndpoint reports the host:port a DSN resolves to, for callers that want to
// probe reachability without opening a pool. Only the primary host is returned;
// pgx fallbacks are not considered.
func DSNEndpoint(dsn string) (string, error) {
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(cfg.Host, strconv.Itoa(int(cfg.Port))), nil
}

// isLoopbackHost reports whether host stays on this machine. Unix socket
// directories are rejected along with everything non-loopback: OpenLocal is an
// escape hatch, so it accepts only the two forms a local dev database actually
// needs and leaves the rest to the Vault path.
func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (s *Store) Close() {
	if s.pool != nil {
		s.pool.Close()
	}
}

// ipArrayCol renders an inet[] column as a text[] of bare host addresses so it
// scans straight into a []string. expr is the column reference (optionally
// table-qualified), e.g. "extra_ips", "srv.extra_ips", "ss.observed_ips".
func ipArrayCol(expr string) string {
	return `coalesce((SELECT array_agg(host(x)) FROM unnest(` + expr + `) AS x), ARRAY[]::text[])`
}

// extraIPsCol is ipArrayCol for servers.extra_ips. prefix is the table alias
// plus a dot ("" for an unqualified query, "srv." for a join).
func extraIPsCol(prefix string) string { return ipArrayCol(prefix + "extra_ips") }

var selectCols = `hostname, host(ip), ssh_port, ssh_user, coalesce(jump_via,''), dc, ca_role, ca_key_version, last_seen_up, ` + extraIPsCol("") + `, coalesce(state,'active')`

func scanServer(row interface {
	Scan(dest ...any) error
}) (Server, error) {
	var sv Server
	err := row.Scan(&sv.Hostname, &sv.IP, &sv.Port, &sv.User, &sv.JumpVia, &sv.DC, &sv.CARole, &sv.CAKeyVersion, &sv.LastSeenUp, &sv.ExtraIPs, &sv.State)
	return sv, err
}

// Get returns one exact hostname match.
func (s *Store) Get(ctx context.Context, hostname string) (*Server, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+selectCols+` FROM servers WHERE hostname=$1`, hostname)
	sv, err := scanServer(row)
	if err != nil {
		return nil, err
	}
	return &sv, nil
}

// collectRows drains rows through scan and closes them, standardizing the
// for-rows.Next()/Scan/Err loop repeated across the store.
func collectRows[T any](rows pgx.Rows, scan func(pgx.Rows) (T, error)) ([]T, error) {
	defer rows.Close()
	var out []T
	for rows.Next() {
		v, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func scanServerRow(r pgx.Rows) (Server, error) { return scanServer(r) }

// rowQuerier is the read half of a pool or a transaction.
//
// Both *pgxpool.Pool and pgx.Tx satisfy it, which is the point: a read can run
// on its own or as part of one consistent snapshot without a second copy of the
// query existing to drift from the first.
type rowQuerier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// queryAndCollect runs a query and drains the rows through scan, closing them —
// the one-shot Query+collectRows used across the store.
func queryAndCollect[T any](ctx context.Context, db rowQuerier, q string, args []any, scan func(pgx.Rows) (T, error)) ([]T, error) {
	rows, err := db.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	return collectRows(rows, scan)
}

// scanString scans a single text column (the common one-column query shape).
func scanString(r pgx.Rows) (string, error) {
	var v string
	err := r.Scan(&v)
	return v, err
}

// Resolve tries exact hostname match first, then — if the query is an IP — any
// host answering on that address (primary ip, operator-set extra_ips, or
// node-agent observed_ips), and otherwise fuzzy hostname matching.
// One match returns server; multiple matches return candidates.
func (s *Store) Resolve(ctx context.Context, query string) (*Server, []Server, error) {
	if sv, err := s.Get(ctx, query); err == nil {
		return sv, nil, nil
	}

	where := `hostname ILIKE '%'||$1||'%'`
	if net.ParseIP(query) != nil {
		// The exact predicates use the btree/GIN indexes for the normal host-mask
		// representation. The host() fallbacks preserve compatibility with legacy
		// INET values such as 192.0.2.10/24, whose prefix participates in equality.
		where = `(ip=$1::inet OR host(ip)=host($1::inet)) OR ` +
			`(extra_ips @> ARRAY[$1::inet] OR EXISTS (SELECT 1 FROM unnest(extra_ips) a WHERE host(a)=host($1::inet))) OR ` +
			`hostname IN (SELECT hostname FROM server_status WHERE ` +
			`observed_ips @> ARRAY[$1::inet] OR EXISTS (SELECT 1 FROM unnest(observed_ips) a WHERE host(a)=host($1::inet)))`
	}
	rows, err := s.pool.Query(ctx, `SELECT `+selectCols+` FROM servers WHERE `+where+` ORDER BY hostname`, query)
	if err != nil {
		return nil, nil, err
	}
	cands, err := collectRows(rows, scanServerRow)
	if err != nil {
		return nil, nil, err
	}
	if len(cands) == 1 {
		return &cands[0], nil, nil
	}
	return nil, cands, nil
}

// List returns all servers or those matching a DC filter.
func (s *Store) List(ctx context.Context, dc string) ([]Server, error) {
	q := `SELECT ` + selectCols + ` FROM servers`
	var args []any
	if dc != "" {
		q += ` WHERE dc=$1`
		args = append(args, dc)
	}
	q += ` ORDER BY dc, hostname`
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	return collectRows(rows, scanServerRow)
}

// InventoryRow is one inventory host together with the full set of addresses it
// answers on — primary IP, operator-set extra IPs, and agent-observed IPs —
// deduped with the primary first. It also carries the node-agent heartbeat
// (AgentSeen/AgentVersion, nil when no agent has ever reported) so `vctl list`
// can show which hosts have a live agent. Full runtime metrics (load/memory/
// disk) stay in the status-aware views (the ssh picker, `vctl status`).
type InventoryRow struct {
	Server
	Addresses    []string
	AgentSeen    *time.Time // last node-agent heartbeat; nil = no agent
	AgentVersion string
}

// ListInventory returns inventory rows (optionally filtered by DC) with their
// merged address set and the node-agent heartbeat. It LEFT JOINs server_status
// for observed_ips (so `vctl ssh --server <ip>` matches) plus last_seen_at and
// agent_version (so the listing can flag agent liveness) — not the full metrics.
func (s *Store) ListInventory(ctx context.Context, dc string) ([]InventoryRow, error) {
	q := `SELECT ` + prefixedSelectCols("srv") + `, ` + ipArrayCol("ss.observed_ips") + `,
		ss.last_seen_at, coalesce(ss.agent_version,'')
		FROM servers srv
		LEFT JOIN server_status ss ON ss.hostname = srv.hostname`
	var args []any
	if dc != "" {
		q += ` WHERE srv.dc=$1`
		args = append(args, dc)
	}
	q += ` ORDER BY srv.dc, srv.hostname`
	return queryAndCollect(ctx, s.pool, q, args, func(r pgx.Rows) (InventoryRow, error) {
		var row InventoryRow
		var observed []string
		err := r.Scan(&row.Hostname, &row.IP, &row.Port, &row.User, &row.JumpVia, &row.DC,
			&row.CARole, &row.CAKeyVersion, &row.LastSeenUp, &row.ExtraIPs, &row.State, &observed,
			&row.AgentSeen, &row.AgentVersion)
		if err != nil {
			return row, err
		}
		row.Addresses = mergeAddresses(row.IP, row.ExtraIPs, observed)
		return row, nil
	})
}

// mergeAddresses returns the primary address first, then the extra and observed
// sets, deduplicated and with empties dropped.
func mergeAddresses(primary string, sets ...[]string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(ip string) {
		if ip != "" && !seen[ip] {
			seen[ip] = true
			out = append(out, ip)
		}
	}
	add(primary)
	for _, set := range sets {
		for _, ip := range set {
			add(ip)
		}
	}
	return out
}

// AccessEntry is one row of the inventory-level SSH access audit.
type AccessEntry struct {
	VaultUser  string
	Hostname   string
	CertSerial string
	SignedAt   time.Time
	OK         bool
	SourceIP   string
	SourceAddr string
	ClientHost string
	ClientUser string
	TargetAddr string
	JumpVia    string
	Error      string
}

// LogAccess appends one SSH access record to access_log. It requires write
// credentials and is meant to be called best-effort after a connection attempt.
//
// SignedAt is honoured when set and defaults to now() otherwise. Live calls
// leave it zero and let the database stamp the row; a record replayed from the
// local spool after a Postgres outage carries the time the connection actually
// happened, so the audit trail does not compress an outage's worth of access
// into the moment connectivity returned.
func (s *Store) LogAccess(ctx context.Context, e AccessEntry) error {
	var signedAt any
	if !e.SignedAt.IsZero() {
		signedAt = e.SignedAt
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO access_log
			(vault_user, hostname, cert_serial, ok, source_ip, source_addr, client_host, client_user, target_addr, jump_via, error, signed_at)
		VALUES ($1,$2,$3,$4,NULLIF($5,'')::inet,$6,$7,$8,$9,$10,$11, coalesce($12::timestamptz, now()))`,
		nullIfEmpty(e.VaultUser), nullIfEmpty(e.Hostname), nullIfEmpty(e.CertSerial), e.OK, e.SourceIP,
		nullIfEmpty(e.SourceAddr), nullIfEmpty(e.ClientHost), nullIfEmpty(e.ClientUser), nullIfEmpty(e.TargetAddr),
		nullIfEmpty(e.JumpVia), nullIfEmpty(e.Error), signedAt)
	return err
}

// AccessLog returns recent access_log rows, newest first, optionally filtered by
// hostname/vault_user substrings. limit<=0 defaults to 50.
func (s *Store) AccessLog(ctx context.Context, limit int, hostFilter, userFilter, sourceIPFilter string) ([]AccessEntry, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx, `
		SELECT coalesce(vault_user,''), coalesce(hostname,''), coalesce(cert_serial,''), signed_at, coalesce(ok,false),
		       coalesce(host(source_ip),''), coalesce(source_addr,''), coalesce(client_host,''), coalesce(client_user,''),
		       coalesce(target_addr,''), coalesce(jump_via,''), coalesce(error,'')
		FROM access_log
		WHERE ($1='' OR hostname ILIKE '%'||$1||'%')
		  AND ($2='' OR vault_user ILIKE '%'||$2||'%')
		  AND ($3='' OR host(source_ip) = $3)
		ORDER BY signed_at DESC
		LIMIT $4`, hostFilter, userFilter, sourceIPFilter, limit)
	if err != nil {
		return nil, err
	}
	return collectRows(rows, func(r pgx.Rows) (AccessEntry, error) {
		var e AccessEntry
		err := r.Scan(&e.VaultUser, &e.Hostname, &e.CertSerial, &e.SignedAt, &e.OK, &e.SourceIP, &e.SourceAddr, &e.ClientHost, &e.ClientUser, &e.TargetAddr, &e.JumpVia, &e.Error)
		return e, err
	})
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// Upsert reconciles one probed host during sync. It requires write credentials.
//
// An already-known host is matched by IP and its operator-managed identity and
// topology — hostname, dc, ssh_user, jump_via — are PRESERVED; only the probe
// fields refresh (last_seen_up, ssh_port, ca_role). So operator edits (DC moves,
// renames, ssh-user overrides) stay sticky across syncs and a renamed host is
// never re-inserted under its ssh-config alias. A genuinely new IP is inserted
// with the sync-derived values (initial DC classification etc.).
func (s *Store) Upsert(ctx context.Context, sv Server) error {
	var jump any
	if sv.JumpVia != "" {
		jump = sv.JumpVia
	}

	// Known host (by IP): refresh liveness only, preserve operator fields.
	var existing []string
	err := s.pool.QueryRow(ctx,
		// Equality is the indexed common path; host() keeps legacy masked INET
		// values from being mistaken for a new machine during synchronization.
		`SELECT coalesce(array_agg(hostname ORDER BY hostname), '{}') FROM servers
		 WHERE ip=$1::inet OR host(ip)=host($1::inet)`,
		sv.IP).Scan(&existing)
	if err != nil {
		return err
	}
	switch len(existing) {
	case 1:
		_, err = s.pool.Exec(ctx, `
			UPDATE servers SET ssh_port=$2, ca_role=$3, last_seen_up=$4, updated_at=now()
			WHERE hostname=$1`, existing[0], sv.Port, sv.CARole, sv.LastSeenUp)
		return err
	case 0:
		// New address; insert below.
	default:
		return fmt.Errorf("primary IP %s belongs to multiple servers: %s", sv.IP, strings.Join(existing, ", "))
	}

	// New host: insert sync-derived values. The hostname conflict fallback also
	// preserves operator dc/ssh_user/jump_via (only refreshes probe fields).
	_, err = s.pool.Exec(ctx, `
		INSERT INTO servers (hostname, ip, ssh_port, ssh_user, jump_via, dc, ca_role, last_seen_up, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8, now())
		ON CONFLICT (hostname) DO UPDATE SET
			ip=EXCLUDED.ip, ssh_port=EXCLUDED.ssh_port, ca_role=EXCLUDED.ca_role,
			last_seen_up=EXCLUDED.last_seen_up, updated_at=now()`,
		sv.Hostname, sv.IP, sv.Port, sv.User, jump, sv.DC, sv.CARole, sv.LastSeenUp)
	return err
}
