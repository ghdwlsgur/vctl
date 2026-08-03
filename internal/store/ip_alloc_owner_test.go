package store

import (
	"context"
	"testing"
)

// The column shipped with migration 014 and had no writer: IPAllocUpsert writes
// every column from its struct and does not mention this one, so a VIP could be
// recorded but never bound. Integration — needs VCTL_TEST_DSN.
func TestIPAllocSetOwnerKeyStoresAndClears(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	const ip = "198.51.100.231"

	_, _ = st.pool.Exec(ctx, `DELETE FROM ip_allocations WHERE ip=$1`, ip)
	if err := st.IPAllocUpsert(ctx, IPAllocation{
		IP: ip, Owner: "sre", Kind: "dnat-vip", Label: "test vip", Note: "n",
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	t.Cleanup(func() { _, _ = st.pool.Exec(ctx, `DELETE FROM ip_allocations WHERE ip=$1`, ip) })

	read := func() IPAllocation {
		t.Helper()
		rows, err := st.IPAllocList(ctx, "", "", "")
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		for _, a := range rows {
			if a.IP == ip {
				return a
			}
		}
		t.Fatalf("%s missing", ip)
		return IPAllocation{}
	}

	if got := read().OwnerPublicKey; got != "" {
		t.Errorf("a fresh row has owner key %q, want empty", got)
	}
	ok, err := st.IPAllocSetOwnerKey(ctx, ip, "PUBKEYAAA")
	if err != nil || !ok {
		t.Fatalf("SetOwnerKey: %v ok=%v", err, ok)
	}
	if got := read().OwnerPublicKey; got != "PUBKEYAAA" {
		t.Errorf("owner key = %q, want the stored value", got)
	}

	// A later `vctl ip set` must not silently drop the binding — that command
	// rewrites the row from its flags and does not know about this column.
	if err := st.IPAllocUpsert(ctx, IPAllocation{
		IP: ip, Owner: "sre", Kind: "dnat-vip", Label: "test vip renamed",
	}); err != nil {
		t.Fatalf("re-upsert: %v", err)
	}
	if got := read().OwnerPublicKey; got != "PUBKEYAAA" {
		t.Errorf("owner key = %q after an unrelated upsert; the binding was lost", got)
	}

	// Clearing is how a wrong binding is undone.
	if _, err := st.IPAllocSetOwnerKey(ctx, ip, ""); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if got := read().OwnerPublicKey; got != "" {
		t.Errorf("owner key = %q after clearing", got)
	}
}

// A binding on an address nobody recorded would be invisible, so say so.
// Integration — needs VCTL_TEST_DSN.
func TestIPAllocSetOwnerKeyReportsAMissingAddress(t *testing.T) {
	st := testStore(t)
	ok, err := st.IPAllocSetOwnerKey(context.Background(), "198.51.100.254", "K")
	if err != nil {
		t.Fatalf("SetOwnerKey: %v", err)
	}
	if ok {
		t.Error("reported a match for an address that is not in the ledger")
	}
}
