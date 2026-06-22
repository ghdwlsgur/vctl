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
}

type Store struct {
	pool *pgxpool.Pool
}

// Open creates a Postgres pool with short-lived credentials and caPEM TLS roots.
// serverName overrides the TLS SNI/verification name; when empty it defaults to host.
// Use serverName when dialing through a port-forward/proxy where the dial host
// (e.g. 127.0.0.1) differs from the certificate's DNS name.
func Open(ctx context.Context, host string, port int, dbname string, getCreds CredsFunc, serverName string, caPEM []byte) (*Store, error) {
	// No userinfo in the DSN: credentials are injected per-connection by
	// BeforeConnect so the pool can refresh them as dynamic leases roll over.
	dsn := fmt.Sprintf("postgres://%s:%d/%s", host, port, dbname)

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
	cfg.MaxConns = 4
	// Vault dynamic DB creds default to a 1h TTL (max 4h). Recycle connections
	// well inside that window so each physical connection re-fetches a live
	// credential via BeforeConnect; an expired lease is never reused. This is
	// what lets the long-running collector/watch daemons run without a restart.
	cfg.MaxConnLifetime = 30 * time.Minute
	cfg.MaxConnLifetimeJitter = 5 * time.Minute
	cfg.MaxConnIdleTime = 5 * time.Minute
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

func (s *Store) Close() {
	if s.pool != nil {
		s.pool.Close()
	}
}

const selectCols = `hostname, host(ip), ssh_port, ssh_user, coalesce(jump_via,''), dc, ca_role, ca_key_version, last_seen_up`

func scanServer(row interface {
	Scan(dest ...any) error
}) (Server, error) {
	var sv Server
	err := row.Scan(&sv.Hostname, &sv.IP, &sv.Port, &sv.User, &sv.JumpVia, &sv.DC, &sv.CARole, &sv.CAKeyVersion, &sv.LastSeenUp)
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

// Resolve tries exact match first, then fuzzy hostname matching.
// One match returns server; multiple matches return candidates.
func (s *Store) Resolve(ctx context.Context, query string) (*Server, []Server, error) {
	if sv, err := s.Get(ctx, query); err == nil {
		return sv, nil, nil
	}
	rows, err := s.pool.Query(ctx,
		`SELECT `+selectCols+` FROM servers WHERE hostname ILIKE '%'||$1||'%' ORDER BY hostname`, query)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var cands []Server
	for rows.Next() {
		sv, err := scanServer(rows)
		if err != nil {
			return nil, nil, err
		}
		cands = append(cands, sv)
	}
	if len(cands) == 1 {
		return &cands[0], nil, nil
	}
	return nil, cands, rows.Err()
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
	defer rows.Close()
	var out []Server
	for rows.Next() {
		sv, err := scanServer(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sv)
	}
	return out, rows.Err()
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
func (s *Store) LogAccess(ctx context.Context, e AccessEntry) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO access_log
			(vault_user, hostname, cert_serial, ok, source_ip, source_addr, client_host, client_user, target_addr, jump_via, error)
		VALUES ($1,$2,$3,$4,NULLIF($5,'')::inet,$6,$7,$8,$9,$10,$11)`,
		nullIfEmpty(e.VaultUser), nullIfEmpty(e.Hostname), nullIfEmpty(e.CertSerial), e.OK, e.SourceIP,
		nullIfEmpty(e.SourceAddr), nullIfEmpty(e.ClientHost), nullIfEmpty(e.ClientUser), nullIfEmpty(e.TargetAddr),
		nullIfEmpty(e.JumpVia), nullIfEmpty(e.Error))
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
	defer rows.Close()
	var out []AccessEntry
	for rows.Next() {
		var e AccessEntry
		if err := rows.Scan(&e.VaultUser, &e.Hostname, &e.CertSerial, &e.SignedAt, &e.OK, &e.SourceIP, &e.SourceAddr, &e.ClientHost, &e.ClientUser, &e.TargetAddr, &e.JumpVia, &e.Error); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// Upsert updates one host record during sync. It requires write credentials.
func (s *Store) Upsert(ctx context.Context, sv Server) error {
	var jump any
	if sv.JumpVia != "" {
		jump = sv.JumpVia
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO servers (hostname, ip, ssh_port, ssh_user, jump_via, dc, ca_role, last_seen_up, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8, now())
		ON CONFLICT (hostname) DO UPDATE SET
			ip=EXCLUDED.ip, ssh_port=EXCLUDED.ssh_port, ssh_user=EXCLUDED.ssh_user,
			jump_via=EXCLUDED.jump_via, dc=EXCLUDED.dc, ca_role=EXCLUDED.ca_role,
			last_seen_up=EXCLUDED.last_seen_up, updated_at=now()`,
		sv.Hostname, sv.IP, sv.Port, sv.User, jump, sv.DC, sv.CARole, sv.LastSeenUp)
	return err
}
