package cli

import (
	"testing"

	"github.com/ghdwlsgur/vctl/internal/store"
)

// The bug this guards: `wg endpoint set <key> --inventory-host h` on a row
// annotated as a physical host used to write kind=device (the flag default) and
// an empty note, because the flags were the row. Only passed flags may change.
func TestEndpointSetMergesOverTheStoredRow(t *testing.T) {
	current := &store.WGEndpointAnnotation{
		PublicKey: "K1", Label: "worker-1", Kind: "physical-host", UnderlayIP: "192.0.2.7",
		TunnelIP: "10.0.93.7", Site: "site-a", Note: "racked 2026-01",
	}
	flags := store.WGEndpointAnnotation{PublicKey: "K1", Kind: "device", InventoryHost: "worker-1.example"}
	changed := func(name string) bool { return name == "inventory-host" }

	got := mergeEndpointAnnotation(current, flags, changed)
	want := *current
	want.InventoryHost = "worker-1.example"
	if got != want {
		t.Fatalf("merge changed more than the passed flag:\n got %+v\nwant %+v", got, want)
	}
}

// Passing a flag as empty is a deliberate clear, and must not be mistaken for
// "not passed".
func TestEndpointSetClearsAFieldPassedEmpty(t *testing.T) {
	current := &store.WGEndpointAnnotation{PublicKey: "K1", Kind: "vm", Note: "old note", ParentHostname: "h1"}
	flags := store.WGEndpointAnnotation{PublicKey: "K1", Kind: "device"}
	changed := func(name string) bool { return name == "note" }
	got := mergeEndpointAnnotation(current, flags, changed)
	if got.Note != "" || got.ParentHostname != "h1" || got.Kind != "vm" {
		t.Fatalf("clearing note should touch only note: %+v", got)
	}
}

// With nothing stored the flags are the row, defaults included — the first
// `set` on a key behaves as it always did.
func TestEndpointSetWithoutAStoredRowUsesTheFlags(t *testing.T) {
	flags := store.WGEndpointAnnotation{PublicKey: "K2", Kind: "device", Label: "new"}
	got := mergeEndpointAnnotation(nil, flags, func(string) bool { return false })
	if got != flags {
		t.Fatalf("no stored row: got %+v, want the flags %+v", got, flags)
	}
	if err := validateEndpointAnnotation(store.WGEndpointAnnotation{Kind: "router"}); err == nil {
		t.Fatalf("an unknown kind must still be rejected after the merge")
	}
}
