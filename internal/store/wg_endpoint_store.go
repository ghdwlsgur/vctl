package store

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// WGEndpointAnnotation gives an operator-owned identity and placement to a
// WireGuard public key. Collection never overwrites this data: it is the stable
// bridge from a cryptographic endpoint to the VM/device and physical host that
// run it.
type WGEndpointAnnotation struct {
	PublicKey      string
	Label          string
	Kind           string // vm | physical-host | device | gateway
	UnderlayIP     string // host/vNIC address used for physical network placement
	TunnelIP       string // WireGuard overlay address; never used for host-network placement
	Site           string
	InventoryHost  string
	ParentHostname string
	Note           string
}

const wgEndpointAnnotationCols = `public_key, label, kind, coalesce(host(underlay_ip),''),
	coalesce(host(tunnel_ip),''), site, inventory_host, parent_hostname, note`

func scanWGEndpointAnnotation(r pgx.Rows) (WGEndpointAnnotation, error) {
	var a WGEndpointAnnotation
	err := r.Scan(&a.PublicKey, &a.Label, &a.Kind, &a.UnderlayIP, &a.TunnelIP, &a.Site,
		&a.InventoryHost, &a.ParentHostname, &a.Note)
	return a, err
}

// WGEndpointAnnotations returns the operator-owned endpoint identities used to
// enrich topology. Collection timestamps and runtime state remain in the WG
// collection tables.
func (s *Store) WGEndpointAnnotations(ctx context.Context) ([]WGEndpointAnnotation, error) {
	return queryAndCollect(ctx, s.pool, `
		SELECT `+wgEndpointAnnotationCols+`
		FROM wg_endpoint_annotations
		ORDER BY site, parent_hostname, label, public_key`,
		nil, scanWGEndpointAnnotation)
}

// WGEndpointAnnotationUpsert creates or replaces one endpoint identity.
func (s *Store) WGEndpointAnnotationUpsert(ctx context.Context, a WGEndpointAnnotation) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO wg_endpoint_annotations
			(public_key, label, kind, underlay_ip, tunnel_ip, site, inventory_host, parent_hostname, note, updated_at)
		VALUES ($1,$2,$3,NULLIF($4,'')::inet,NULLIF($5,'')::inet,$6,$7,$8,$9,now())
		ON CONFLICT (public_key) DO UPDATE SET
			label=EXCLUDED.label, kind=EXCLUDED.kind, underlay_ip=EXCLUDED.underlay_ip,
			tunnel_ip=EXCLUDED.tunnel_ip,
			site=EXCLUDED.site, inventory_host=EXCLUDED.inventory_host,
			parent_hostname=EXCLUDED.parent_hostname, note=EXCLUDED.note,
			updated_at=now()`,
		a.PublicKey, a.Label, a.Kind, a.UnderlayIP, a.TunnelIP, a.Site, a.InventoryHost,
		a.ParentHostname, a.Note)
	return err
}

// WGEndpointAnnotationDelete removes one operator annotation. Collected WG
// state remains intact and the endpoint falls back to inventory/IP resolution.
func (s *Store) WGEndpointAnnotationDelete(ctx context.Context, publicKey string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM wg_endpoint_annotations WHERE public_key=$1`, publicKey)
	return err
}
