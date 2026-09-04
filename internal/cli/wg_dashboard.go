package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/wireguard"
)

// The dashboard, in three pieces: what is drawn, what moves on it, and what
// serves it.
//
// All three used to be one RunE. That function opened the store, ran six
// queries, joined two inventories, resolved SSH targets, started a goroutine per
// gateway, mounted three routes and handled shutdown — so none of it could be
// exercised without a database, a Vault token and twelve reachable gateways, and
// in practice none of it was. This file is the first piece.
//
// dashboardSnapshot is one reading of the database, assembled into the drawing
// the page asks for. Nothing here polls, listens, or contacts a gateway: the
// picture is what the last `vctl wg sync` recorded, and the traffic on it
// arrives separately and later.
type dashboardSnapshot struct {
	Topo wireguard.Topology
	// EdgeFor maps a polled tunnel back to the edge it is drawn as. The poller
	// needs it to file a sample against the right line; it is produced here
	// because it falls out of building the topology and deriving it twice is
	// how two views of one tunnel start to disagree.
	EdgeFor map[wireguard.TunnelKey]string
}

// loadDashboardSnapshot reads everything the drawing needs, in one pass over one
// store.
//
// warn takes the failures that do not stop the drawing. Site grouping, endpoint
// annotations and the OpenStack join each make the picture better and none of
// them make it wrong by their absence — a dashboard that refuses to open because
// one enrichment query failed is worse than one that opens with plainer boxes.
// The two that do stop it are the interfaces and peers themselves, because
// without them there is nothing to draw.
func loadDashboardSnapshot(ctx context.Context, st *store.Store, warn func(format string, args ...any)) (*dashboardSnapshot, error) {
	ifaces, err := st.WGInterfaces(ctx)
	if err != nil {
		return nil, err
	}
	if len(ifaces) == 0 {
		return nil, fmt.Errorf("no WireGuard data; run 'vctl wg sync' first")
	}
	peers, err := st.WGPeers(ctx)
	if err != nil {
		return nil, err
	}

	servers, err := st.List(ctx, "")
	if err != nil {
		warn("list servers for site grouping: %v", err)
	}
	annotations, err := st.WGEndpointAnnotations(ctx)
	if err != nil {
		warn("list endpoint annotations (run vctl sync --migrate): %v", err)
	}
	instances, err := st.Instances(ctx, store.InstanceFilter{})
	if err != nil {
		warn("list OpenStack VMs for endpoint placement: %v", err)
	}
	osHosts, err := st.OpenStackHosts(ctx)
	if err != nil {
		warn("list OpenStack hosts for endpoint placement: %v", err)
	}
	annotations = enrichWGAnnotations(ifaces, servers, annotations, instances, osHosts)

	topo, edgeFor := wireguard.Build(ifaces, peers, servers, annotations)
	// DNAT VIPs come from the IPAM ledger, which is a different record with a
	// different owner — a failure to read it is not a failure to draw the
	// fabric, so it is dropped rather than warned about.
	if vips, err := st.IPAllocList(ctx, "dnat-vip", "", ""); err == nil {
		for _, v := range vips {
			note := strings.TrimSpace(strings.TrimSpace(v.OS) + " " + strings.TrimSpace(v.Note))
			topo.Vips = append(topo.Vips, wireguard.Vip{
				IP: v.IP, Label: v.Label, Iface: v.WGTunnel, Note: note,
				Owner: v.OwnerPublicKey,
			})
		}
	}
	return &dashboardSnapshot{Topo: topo, EdgeFor: edgeFor}, nil
}
