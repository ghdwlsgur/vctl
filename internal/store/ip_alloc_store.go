package store

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// IPAllocation is one row of the 192.168.201.0/24 address ledger (IPAM). It is
// operator-managed and, unlike servers, never touched by sync — it holds
// personal devices, OpenStack VMs, floating IPs and DNAT VIPs alongside the
// physical hosts.
type IPAllocation struct {
	IP       string
	Owner    string
	Kind     string // personal | server | vm | floating-ip | dnat-vip
	Label    string
	Hostname string // links to servers.hostname when kind=server (may be empty)
	OS       string
	Project  string
	Farm     string
	FarmVIP  string
	Rack     string
	Location string
	WGTunnel string
	Status   string
	Note     string
}

// scanIPAllocation reads one row; it takes the minimal Scan interface so both
// pgx.Row (QueryRow) and pgx.Rows (Query) satisfy it, mirroring scanServer.
func scanIPAllocation(row interface {
	Scan(dest ...any) error
}) (IPAllocation, error) {
	var a IPAllocation
	err := row.Scan(&a.IP, &a.Owner, &a.Kind, &a.Label, &a.Hostname, &a.OS, &a.Project,
		&a.Farm, &a.FarmVIP, &a.Rack, &a.Location, &a.WGTunnel, &a.Status, &a.Note)
	return a, err
}

func scanIPAllocRow(r pgx.Rows) (IPAllocation, error) { return scanIPAllocation(r) }

// ipAllocCols selects every column with nullable text/inet coalesced to '' so a
// row scans straight into IPAllocation without null handling.
const ipAllocCols = `host(ip), owner, kind, label, coalesce(hostname,''), coalesce(os,''), ` +
	`coalesce(project,''), coalesce(farm,''), coalesce(host(farm_vip),''), coalesce(rack,''), ` +
	`coalesce(location,''), coalesce(wg_tunnel,''), status, note`

// IPAllocList returns ledger rows ordered by address, optionally filtered by
// kind, owner (substring), and a free-text substring across owner/label/
// project/note. Empty filters match everything.
func (s *Store) IPAllocList(ctx context.Context, kind, owner, filter string) ([]IPAllocation, error) {
	q := `SELECT ` + ipAllocCols + ` FROM ip_allocations
		WHERE ($1='' OR kind=$1)
		  AND ($2='' OR owner ILIKE '%'||$2||'%')
		  AND ($3='' OR owner||' '||label||' '||coalesce(project,'')||' '||note ILIKE '%'||$3||'%')
		ORDER BY ip`
	return queryAndCollect(ctx, s.pool, q, []any{kind, owner, filter}, scanIPAllocRow)
}

// IPAllocGet returns one allocation by exact address, or pgx.ErrNoRows.
func (s *Store) IPAllocGet(ctx context.Context, ip string) (*IPAllocation, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+ipAllocCols+` FROM ip_allocations WHERE ip=$1`, ip)
	a, err := scanIPAllocation(row)
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// IPAllocUpsert creates or replaces one allocation keyed by IP. Requires write
// credentials. Empty hostname/farm_vip become NULL so the nullable columns stay
// clean; status defaults to "active".
func (s *Store) IPAllocUpsert(ctx context.Context, a IPAllocation) error {
	status := a.Status
	if status == "" {
		status = "active"
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO ip_allocations
			(ip, owner, kind, label, hostname, os, project, farm, farm_vip, rack, location, wg_tunnel, status, note, updated_at)
		VALUES ($1,$2,$3,$4,NULLIF($5,''),NULLIF($6,''),NULLIF($7,''),NULLIF($8,''),NULLIF($9,'')::inet,NULLIF($10,''),NULLIF($11,''),NULLIF($12,''),$13,$14, now())
		ON CONFLICT (ip) DO UPDATE SET
			owner=EXCLUDED.owner, kind=EXCLUDED.kind, label=EXCLUDED.label, hostname=EXCLUDED.hostname,
			os=EXCLUDED.os, project=EXCLUDED.project, farm=EXCLUDED.farm, farm_vip=EXCLUDED.farm_vip,
			rack=EXCLUDED.rack, location=EXCLUDED.location, wg_tunnel=EXCLUDED.wg_tunnel,
			status=EXCLUDED.status, note=EXCLUDED.note, updated_at=now()`,
		a.IP, a.Owner, a.Kind, a.Label, a.Hostname, a.OS, a.Project, a.Farm, a.FarmVIP,
		a.Rack, a.Location, a.WGTunnel, status, a.Note)
	return err
}

// IPAllocDelete removes one allocation by IP. Idempotent.
func (s *Store) IPAllocDelete(ctx context.Context, ip string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM ip_allocations WHERE ip=$1`, ip)
	return err
}
