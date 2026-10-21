package store

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ghdwlsgur/vctl/internal/hwspec"
)

// ServerSpec is the hardware a collector last reported for a host.
type ServerSpec struct {
	Hostname   string
	Source     string // agent | vsphere
	Spec       hwspec.Spec
	Collector  string
	ObservedAt time.Time
}

// Spec sources.
const (
	SpecSourceAgent   = "agent"
	SpecSourceVSphere = "vsphere"
)

// UpsertServerSpec replaces a host's spec with one collection.
//
// Whole-row replace, not a merge: a DIMM pulled out of the machine must
// disappear from the record, and merging would keep it forever. Refuses to
// create inventory the way UpsertServerStatus does — false for a hostname not
// in servers.
func (s *Store) UpsertServerSpec(ctx context.Context, sp ServerSpec) (bool, error) {
	body, err := json.Marshal(sp.Spec)
	if err != nil {
		return false, err
	}
	tag, err := s.pool.Exec(ctx, `
		INSERT INTO server_specs (hostname, source, spec, collector, observed_at, updated_at)
		SELECT $1, $2, $3::jsonb, NULLIF($4,''), now(), now()
		WHERE EXISTS (SELECT 1 FROM servers WHERE hostname=$1)
		ON CONFLICT (hostname) DO UPDATE SET
			source=EXCLUDED.source, spec=EXCLUDED.spec, collector=EXCLUDED.collector,
			observed_at=EXCLUDED.observed_at, updated_at=now()`,
		sp.Hostname, sp.Source, string(body), sp.Collector)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// Asset is what operators record about a machine and no collector can know.
type Asset struct {
	Hostname    string
	IDC         string
	Rack        string
	Label       string
	LegacyLabel string
	RackUnits   string
	Usage       string
	Purpose     string
	Solution    string
	Department  string
	RAID        string
	Note        string
	UpdatedBy   string
	UpdatedAt   time.Time
}

// AssetFields are the operator-settable columns, by the name the CLI and CSV
// use for them.
var AssetFields = []string{
	"idc", "rack", "label", "legacy_label", "rack_units", "usage",
	"purpose", "solution", "department", "raid", "note",
}

func assetColumn(field string) (string, bool) {
	for _, f := range AssetFields {
		if f == field {
			return f, true
		}
	}
	return "", false
}

// SetAsset writes the given fields of a host's asset record and leaves the
// rest as they were. An empty value clears that field. Returns false when the
// host is not in inventory.
func (s *Store) SetAsset(ctx context.Context, hostname, by string, fields map[string]string) (bool, error) {
	if len(fields) == 0 {
		return false, fmt.Errorf("no asset fields to set")
	}
	keys := make([]string, 0, len(fields))
	for k := range fields {
		if _, ok := assetColumn(k); !ok {
			return false, fmt.Errorf("unknown asset field %q (known: %s)", k, strings.Join(AssetFields, ", "))
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Column names come from the allowlist above, never from the caller.
	cols := []string{"hostname", "updated_by"}
	vals := []string{"$1", "NULLIF($2,'')"}
	sets := []string{"updated_by=EXCLUDED.updated_by", "updated_at=now()"}
	args := []any{hostname, by}
	for _, k := range keys {
		args = append(args, strings.TrimSpace(fields[k]))
		cols = append(cols, k)
		vals = append(vals, fmt.Sprintf("NULLIF($%d,'')", len(args)))
		sets = append(sets, k+"=EXCLUDED."+k)
	}
	q := `INSERT INTO server_assets (` + strings.Join(cols, ", ") + `, updated_at)
		SELECT ` + strings.Join(vals, ", ") + `, now()
		WHERE EXISTS (SELECT 1 FROM servers WHERE hostname=$1)
		ON CONFLICT (hostname) DO UPDATE SET ` + strings.Join(sets, ", ")
	tag, err := s.pool.Exec(ctx, q, args...)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// SpecRow is one inventory host with whatever is known about its hardware.
// Spec and Asset are nil when nothing has been collected or recorded.
type SpecRow struct {
	Hostname string
	IP       string
	DC       string
	Spec     *ServerSpec
	Asset    *Asset
}

// SpecRows lists every inventory host with its spec and asset record, for the
// sheet view. hostname filters to one host when non-empty.
func (s *Store) SpecRows(ctx context.Context, hostname string) ([]SpecRow, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT s.hostname, host(s.ip), coalesce(s.dc,''),
		       sp.source, sp.spec, coalesce(sp.collector,''), sp.observed_at,
		       a.hostname IS NOT NULL,
		       coalesce(a.idc,''), coalesce(a.rack,''), coalesce(a.label,''), coalesce(a.legacy_label,''),
		       coalesce(a.rack_units,''), coalesce(a.usage,''), coalesce(a.purpose,''), coalesce(a.solution,''),
		       coalesce(a.department,''), coalesce(a.raid,''), coalesce(a.note,''),
		       coalesce(a.updated_by,''), a.updated_at
		FROM servers s
		LEFT JOIN server_specs sp ON sp.hostname = s.hostname
		LEFT JOIN server_assets a ON a.hostname = s.hostname
		WHERE $1 = '' OR s.hostname = $1
		ORDER BY s.hostname`, hostname)
	if err != nil {
		return nil, err
	}
	return collectRows(rows, func(r pgx.Rows) (SpecRow, error) {
		var (
			row       SpecRow
			source    *string
			body      []byte
			collector string
			observed  *time.Time
			hasAsset  bool
			a         Asset
			updatedAt *time.Time
		)
		if err := r.Scan(&row.Hostname, &row.IP, &row.DC,
			&source, &body, &collector, &observed,
			&hasAsset, &a.IDC, &a.Rack, &a.Label, &a.LegacyLabel, &a.RackUnits, &a.Usage,
			&a.Purpose, &a.Solution, &a.Department, &a.RAID, &a.Note, &a.UpdatedBy, &updatedAt); err != nil {
			return row, err
		}
		if source != nil {
			sp := ServerSpec{Hostname: row.Hostname, Source: *source, Collector: collector}
			if observed != nil {
				sp.ObservedAt = *observed
			}
			if err := json.Unmarshal(body, &sp.Spec); err != nil {
				return row, fmt.Errorf("%s: spec: %w", row.Hostname, err)
			}
			row.Spec = &sp
		}
		if hasAsset {
			a.Hostname = row.Hostname
			if updatedAt != nil {
				a.UpdatedAt = *updatedAt
			}
			row.Asset = &a
		}
		return row, nil
	})
}
