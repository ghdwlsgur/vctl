package store

import (
	"context"
	"testing"

	"github.com/ghdwlsgur/vctl/internal/hwspec"
)

// A spec round-trips whole, a second collection replaces the first rather
// than merging into it, and the operator's asset notes survive both.
// Integration — needs VCTL_TEST_DSN.
func TestSpecReplaceKeepsAssets(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	const host = "spec-host-01"
	seedCapabilityHost(t, st, host)
	t.Cleanup(func() {
		_, _ = st.pool.Exec(ctx, `DELETE FROM server_specs WHERE hostname=$1`, host)
		_, _ = st.pool.Exec(ctx, `DELETE FROM server_assets WHERE hostname=$1`, host)
	})

	first := hwspec.Spec{
		System: hwspec.System{Vendor: "HP", Model: "ProLiant DL560 Gen9", Serial: "SGH610V58C"},
		Memory: hwspec.Memory{TotalMB: 32768, SlotsTotal: 48, Modules: []hwspec.Module{
			{Locator: "PROC 1 DIMM 1", SizeMB: 16384, Type: "DDR4", SpeedMHz: 2133},
			{Locator: "PROC 1 DIMM 4", SizeMB: 16384, Type: "DDR4", SpeedMHz: 2133},
		}},
	}
	if ok, err := st.UpsertServerSpec(ctx, ServerSpec{Hostname: host, Source: SpecSourceAgent, Spec: first, Collector: "v1"}); err != nil || !ok {
		t.Fatalf("first upsert: %v ok=%v", err, ok)
	}
	if ok, err := st.SetAsset(ctx, host, "albert", map[string]string{"rack": "A-07", "usage": "사용중"}); err != nil || !ok {
		t.Fatalf("SetAsset: %v ok=%v", err, ok)
	}
	// A DIMM came out.
	second := first
	second.Memory.Modules = first.Memory.Modules[:1]
	second.Memory.TotalMB = 16384
	if ok, err := st.UpsertServerSpec(ctx, ServerSpec{Hostname: host, Source: SpecSourceAgent, Spec: second, Collector: "v2"}); err != nil || !ok {
		t.Fatalf("second upsert: %v ok=%v", err, ok)
	}
	// A partial asset write leaves the other fields alone.
	if _, err := st.SetAsset(ctx, host, "albert", map[string]string{"idc": "가산"}); err != nil {
		t.Fatalf("SetAsset idc: %v", err)
	}

	rows, err := st.SpecRows(ctx, host)
	if err != nil || len(rows) != 1 {
		t.Fatalf("SpecRows: %v rows=%d", err, len(rows))
	}
	r := rows[0]
	if r.Spec == nil || len(r.Spec.Spec.Memory.Modules) != 1 || r.Spec.Collector != "v2" || r.Spec.Spec.System.Serial != "SGH610V58C" {
		t.Fatalf("spec = %+v, want the second collection whole", r.Spec)
	}
	if r.Asset == nil || r.Asset.Rack != "A-07" || r.Asset.Usage != "사용중" || r.Asset.IDC != "가산" || r.Asset.UpdatedBy != "albert" {
		t.Fatalf("asset = %+v, want rack, usage and idc all kept", r.Asset)
	}

	// Clearing a field with an empty value.
	if _, err := st.SetAsset(ctx, host, "albert", map[string]string{"rack": ""}); err != nil {
		t.Fatal(err)
	}
	rows, _ = st.SpecRows(ctx, host)
	if rows[0].Asset.Rack != "" || rows[0].Asset.IDC != "가산" {
		t.Fatalf("after clearing rack: %+v", rows[0].Asset)
	}
}

// Neither writer creates inventory, and an unknown asset field is refused
// before it can reach SQL.
func TestSpecWritersRefuseUnknownHostsAndFields(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	if ok, err := st.UpsertServerSpec(ctx, ServerSpec{Hostname: "no-such-host-spec", Source: SpecSourceAgent}); err != nil || ok {
		t.Fatalf("UpsertServerSpec on unknown host: ok=%v err=%v", ok, err)
	}
	if ok, err := st.SetAsset(ctx, "no-such-host-spec", "x", map[string]string{"rack": "A"}); err != nil || ok {
		t.Fatalf("SetAsset on unknown host: ok=%v err=%v", ok, err)
	}
	if _, err := st.SetAsset(ctx, "no-such-host-spec", "x", map[string]string{"rack; DROP TABLE servers": "A"}); err == nil {
		t.Fatal("unknown field accepted")
	}
}
