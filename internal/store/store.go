// Package store 는 중앙 인벤토리(Postgres)를 다룬다. 비밀은 저장하지 않는다.
//
// 접속은 Vault 가 발급한 단명 자격으로만 이뤄지고, TLS 는 바이너리에 임베드된
// 사설 CA 로 verify-full 검증한다(평문/MITM 차단).
package store

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/url"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Server struct {
	Hostname     string
	IP           string
	Port         int
	User         string
	JumpVia      string // 빈 문자열이면 점프 없음
	DC           string
	CARole       string
	CAKeyVersion int
	LastSeenUp   *time.Time
}

type Store struct {
	pool *pgxpool.Pool
}

// Open 은 단명 자격으로 Postgres 풀을 연다. caPEM 으로 서버 인증서를 검증한다.
func Open(ctx context.Context, host string, port int, dbname, user, pass string, caPEM []byte) (*Store, error) {
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%d/%s",
		url.QueryEscape(user), url.QueryEscape(pass), host, port, dbname)

	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("dsn 파싱: %w", err)
	}
	pool := x509.NewCertPool()
	if len(caPEM) > 0 && !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("임베드 CA 파싱 실패")
	}
	cfg.ConnConfig.TLSConfig = &tls.Config{
		RootCAs:    pool,
		ServerName: host,
		MinVersion: tls.VersionTLS12,
	}
	cfg.MaxConns = 4

	p, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("postgres 연결: %w", err)
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

// Get 은 호스트명 정확 일치 1건을 조회한다.
func (s *Store) Get(ctx context.Context, hostname string) (*Server, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+selectCols+` FROM servers WHERE hostname=$1`, hostname)
	sv, err := scanServer(row)
	if err != nil {
		return nil, err
	}
	return &sv, nil
}

// Resolve 는 정확 일치 → 부분(퍼지) 일치 순으로 후보를 찾는다.
// 정확히 1건이면 (server, nil, nil), 여러 건이면 (nil, candidates, nil).
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

// List 는 전체(또는 DC 필터) 서버를 반환한다.
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

// Upsert 는 sync 가 호스트 1건을 갱신할 때 쓴다(쓰기 자격 필요).
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
