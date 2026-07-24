package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// WGInterface is one WireGuard interface on a gateway (static config). No
// private key is stored — only the public key, which identifies the endpoint.
type WGInterface struct {
	Host       string
	Iface      string
	ListenPort int
	PublicKey  string
	Fwmark     int64
	Address    []string // interface addresses from `ip addr` (may be empty)
}

// WGPeer is one peer on an interface — a topology edge (who this gateway talks
// to and which networks route over the tunnel).
type WGPeer struct {
	Host       string
	Iface      string
	PeerPubKey string
	Endpoint   string
	AllowedIPs []string
	Keepalive  int
	Label      string
}

// WGPeerStatus is the latest runtime snapshot for a peer (for monitoring).
type WGPeerStatus struct {
	Host            string
	Iface           string
	PeerPubKey      string
	LatestHandshake *time.Time
	RxBytes         int64
	TxBytes         int64
}

// WGReplaceHost atomically replaces all WireGuard rows for one host with a fresh
// collection. Deleting first keeps the topology current: peers/interfaces that
// no longer exist on the gateway do not linger. Requires write credentials.
func (s *Store) WGReplaceHost(ctx context.Context, host string, ifaces []WGInterface, peers []WGPeer, statuses []WGPeerStatus) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	for _, tbl := range []string{"wg_peer_status", "wg_peers", "wg_interfaces"} {
		if _, err := tx.Exec(ctx, "DELETE FROM "+tbl+" WHERE host=$1", host); err != nil {
			return err
		}
	}
	for _, i := range ifaces {
		if _, err := tx.Exec(ctx, `
			INSERT INTO wg_interfaces (host, iface, listen_port, public_key, fwmark, address, collected_at)
			VALUES ($1,$2,NULLIF($3,0),$4,NULLIF($5,0),coalesce($6::inet[],'{}'), now())`,
			i.Host, i.Iface, i.ListenPort, i.PublicKey, i.Fwmark, i.Address); err != nil {
			return err
		}
	}
	for _, p := range peers {
		if _, err := tx.Exec(ctx, `
			INSERT INTO wg_peers (host, iface, peer_pubkey, endpoint, allowed_ips, persistent_keepalive, label, collected_at)
			VALUES ($1,$2,$3,NULLIF($4,''),coalesce($5::text[],'{}'),NULLIF($6,0),NULLIF($7,''), now())`,
			p.Host, p.Iface, p.PeerPubKey, p.Endpoint, p.AllowedIPs, p.Keepalive, p.Label); err != nil {
			return err
		}
	}
	for _, st := range statuses {
		if _, err := tx.Exec(ctx, `
			INSERT INTO wg_peer_status (host, iface, peer_pubkey, latest_handshake, rx_bytes, tx_bytes, sampled_at)
			VALUES ($1,$2,$3,$4,$5,$6, now())`,
			st.Host, st.Iface, st.PeerPubKey, st.LatestHandshake, st.RxBytes, st.TxBytes); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// WGInterfaceRow pairs an interface with its host for listing/graphing.
type WGInterfaceRow struct {
	WGInterface
	CollectedAt time.Time
}

// WGInterfaces returns all collected interfaces, ordered by host/iface.
func (s *Store) WGInterfaces(ctx context.Context) ([]WGInterfaceRow, error) {
	return queryAndCollect(ctx, s.pool, `
		SELECT host, iface, coalesce(listen_port,0), public_key, coalesce(fwmark,0),
		       `+ipArrayCol("address")+`, collected_at
		FROM wg_interfaces ORDER BY host, iface`, nil, func(r pgx.Rows) (WGInterfaceRow, error) {
		var w WGInterfaceRow
		err := r.Scan(&w.Host, &w.Iface, &w.ListenPort, &w.PublicKey, &w.Fwmark, &w.Address, &w.CollectedAt)
		return w, err
	})
}

// WGPeerRow is a peer joined with its latest runtime status, for graph/monitor.
type WGPeerRow struct {
	WGPeer
	LatestHandshake *time.Time
	RxBytes         int64
	TxBytes         int64
}

// WGPeers returns all peers with their latest status, ordered by host/iface.
func (s *Store) WGPeers(ctx context.Context) ([]WGPeerRow, error) {
	return queryAndCollect(ctx, s.pool, `
		SELECT p.host, p.iface, p.peer_pubkey, coalesce(p.endpoint,''),
		       coalesce(p.allowed_ips,'{}'), coalesce(p.persistent_keepalive,0), coalesce(p.label,''),
		       ss.latest_handshake, coalesce(ss.rx_bytes,0), coalesce(ss.tx_bytes,0)
		FROM wg_peers p
		LEFT JOIN wg_peer_status ss
		  ON ss.host=p.host AND ss.iface=p.iface AND ss.peer_pubkey=p.peer_pubkey
		ORDER BY p.host, p.iface, p.peer_pubkey`, nil, func(r pgx.Rows) (WGPeerRow, error) {
		var w WGPeerRow
		err := r.Scan(&w.Host, &w.Iface, &w.PeerPubKey, &w.Endpoint, &w.AllowedIPs,
			&w.Keepalive, &w.Label, &w.LatestHandshake, &w.RxBytes, &w.TxBytes)
		return w, err
	})
}
