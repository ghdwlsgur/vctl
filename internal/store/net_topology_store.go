package store

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5"
)

// NetEntityKinds and NetRelationKinds mirror the CHECK constraints in
// 029_net_topology.sql. The CLI validates against these so a typo is rejected
// with a readable message instead of a constraint error from Postgres.
var (
	NetEntityKinds   = []string{"site", "farm", "physical-host", "vm", "network", "tunnel", "edge", "egress"}
	NetRelationKinds = []string{"placed-on", "member-of", "attached-to", "transits", "carries"}
)

// NetEntity is one declared underlay or overlay object. Kind-specific detail
// (a network's cidr, an egress's public ip, a tunnel's host/iface) lives in
// Attrs so that adding a kind does not mean adding a column.
type NetEntity struct {
	ID    string // <kind>/<name>; networks are net/<farm>/<name>
	Kind  string
	Label string
	Site  string
	Attrs map[string]any
	Note  string
}

// NetRelation is a typed, directed edge between two declared entities. For
// `carries`, Attrs.method (direct|proxy|dnat) says how the CIDR is reached and
// the remaining keys describe that method — snat_at/oif for direct, bind/backend
// for proxy, vip/tunnel_ip for dnat.
type NetRelation struct {
	SrcID string
	DstID string
	Kind  string
	Attrs map[string]any
	Note  string
}

const netEntityCols = `id, kind, label, site, attrs, note`

func scanNetEntity(r pgx.Rows) (NetEntity, error) {
	var e NetEntity
	var attrs []byte
	if err := r.Scan(&e.ID, &e.Kind, &e.Label, &e.Site, &attrs, &e.Note); err != nil {
		return e, err
	}
	// Malformed JSON in one row must not fail the whole listing: the row still
	// says what the entity is, which is most of its value.
	_ = json.Unmarshal(attrs, &e.Attrs)
	return e, nil
}

const netRelationCols = `src_id, dst_id, kind, attrs, note`

func scanNetRelation(r pgx.Rows) (NetRelation, error) {
	var rel NetRelation
	var attrs []byte
	if err := r.Scan(&rel.SrcID, &rel.DstID, &rel.Kind, &attrs, &rel.Note); err != nil {
		return rel, err
	}
	_ = json.Unmarshal(attrs, &rel.Attrs)
	return rel, nil
}

// orEmptyAttrs keeps a nil map from serialising as JSON null, which the
// column's NOT NULL DEFAULT '{}' would reject.
func orEmptyAttrs(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return m
}

// NetEntities returns every declared entity, grouped so a listing reads as a
// containment tree: sites, then farms, then the things inside them.
func (s *Store) NetEntities(ctx context.Context) ([]NetEntity, error) {
	return queryAndCollect(ctx, s.pool, `
		SELECT `+netEntityCols+`
		FROM net_entities
		ORDER BY site, kind, id`,
		nil, scanNetEntity)
}

// NetEntityUpsert creates or replaces one declared entity.
func (s *Store) NetEntityUpsert(ctx context.Context, e NetEntity) error {
	attrs, err := json.Marshal(orEmptyAttrs(e.Attrs))
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO net_entities (id, kind, label, site, attrs, note, updated_at)
		VALUES ($1,$2,$3,$4,$5::jsonb,$6,now())
		ON CONFLICT (id) DO UPDATE SET
			kind=EXCLUDED.kind, label=EXCLUDED.label, site=EXCLUDED.site,
			attrs=EXCLUDED.attrs, note=EXCLUDED.note, updated_at=now()`,
		e.ID, e.Kind, e.Label, e.Site, attrs, e.Note)
	return err
}

// NetEntityDelete removes one entity. Relations that reference it go with it
// (ON DELETE CASCADE): a relation to a thing that no longer exists is not a
// fact worth keeping.
func (s *Store) NetEntityDelete(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM net_entities WHERE id=$1`, id)
	return err
}

// NetRelations returns every declared relation, source-major so the edges out
// of one entity sit together.
func (s *Store) NetRelations(ctx context.Context) ([]NetRelation, error) {
	return queryAndCollect(ctx, s.pool, `
		SELECT `+netRelationCols+`
		FROM net_relations
		ORDER BY src_id, kind, dst_id`,
		nil, scanNetRelation)
}

// NetRelationUpsert creates or replaces one relation. Both endpoints must
// already be declared; Postgres enforces that through the foreign keys.
func (s *Store) NetRelationUpsert(ctx context.Context, rel NetRelation) error {
	attrs, err := json.Marshal(orEmptyAttrs(rel.Attrs))
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO net_relations (src_id, dst_id, kind, attrs, note, updated_at)
		VALUES ($1,$2,$3,$4::jsonb,$5,now())
		ON CONFLICT (src_id, dst_id, kind) DO UPDATE SET
			attrs=EXCLUDED.attrs, note=EXCLUDED.note, updated_at=now()`,
		rel.SrcID, rel.DstID, rel.Kind, attrs, rel.Note)
	return err
}

// NetRelationDelete removes one relation by its full key.
func (s *Store) NetRelationDelete(ctx context.Context, srcID, dstID, kind string) error {
	_, err := s.pool.Exec(ctx,
		`DELETE FROM net_relations WHERE src_id=$1 AND dst_id=$2 AND kind=$3`,
		srcID, dstID, kind)
	return err
}
