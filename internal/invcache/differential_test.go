package invcache

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/ghdwlsgur/vctl/internal/store"
)

// The offline reader reimplements Postgres query semantics in Go — ILIKE
// matching with its wildcards, inet equality across three address sets, the
// server_status join. Unit tests can only check that against my understanding of
// those semantics, which is exactly the thing that might be wrong.
//
// So this compares the two implementations directly: same data, same queries,
// real database on one side and the snapshot on the other. A divergence here is
// a host that resolves differently depending on whether the database happens to
// be up, which is the failure this whole feature must not introduce.
//
// Integration — needs VCTL_TEST_DSN pointing at a loopback Postgres.
func TestOfflineReaderMatchesPostgres(t *testing.T) {
	live, snapshot := seedBothReaders(t)
	ctx := context.Background()

	queries := []string{
		"sre-srv-0047",   // exact hostname
		"sre-bastion",    // exact, different DC
		"0047",           // fuzzy substring
		"srv",            // fuzzy, ambiguous
		"sre",            // fuzzy, matches everything
		"SRE-SRV-0047",   // ILIKE is case-insensitive
		"sre_srv_0047",   // '_' is a LIKE wildcard, not a literal
		"sre%0047",       // '%' is a LIKE wildcard
		"198.51.100.47",  // primary ip
		"198.51.100.147", // operator-set extra_ips
		"198.51.100.148", // agent-observed ip
		"198.51.100.99",  // an address nothing answers on
		"no-such-host",   // no match at all
		"",               // empty query
		"0048",           // the host that has a jump chain and status
		"198.51.100.10",  // bastion primary ip
	}

	for _, q := range queries {
		t.Run(fmt.Sprintf("resolve(%q)", q), func(t *testing.T) {
			wantOne, wantCands, wantErr := live.Resolve(ctx, q)
			gotOne, gotCands, gotErr := snapshot.Resolve(ctx, q)
			if (wantErr == nil) != (gotErr == nil) {
				t.Fatalf("error mismatch: postgres=%v snapshot=%v", wantErr, gotErr)
			}
			if name(wantOne) != name(gotOne) {
				t.Errorf("single match: postgres=%q snapshot=%q", name(wantOne), name(gotOne))
			}
			if w, g := names(wantCands), names(gotCands); !reflect.DeepEqual(w, g) {
				t.Errorf("candidates: postgres=%v snapshot=%v", w, g)
			}
		})
	}

	for _, dc := range []string{"", "incheon", "seoul-onprem", "nope"} {
		t.Run(fmt.Sprintf("list(%q)", dc), func(t *testing.T) {
			wantList, err := live.List(ctx, dc)
			if err != nil {
				t.Fatal(err)
			}
			gotList, err := snapshot.List(ctx, dc)
			if err != nil {
				t.Fatal(err)
			}
			if w, g := serverNames(wantList), serverNames(gotList); !reflect.DeepEqual(w, g) {
				t.Errorf("List: postgres=%v snapshot=%v", w, g)
			}

			wantInv, err := live.ListInventory(ctx, dc)
			if err != nil {
				t.Fatal(err)
			}
			gotInv, err := snapshot.ListInventory(ctx, dc)
			if err != nil {
				t.Fatal(err)
			}
			if len(wantInv) != len(gotInv) {
				t.Fatalf("ListInventory length: postgres=%d snapshot=%d", len(wantInv), len(gotInv))
			}
			for i := range wantInv {
				w, g := wantInv[i], gotInv[i]
				if w.Hostname != g.Hostname {
					t.Fatalf("row %d: postgres=%q snapshot=%q", i, w.Hostname, g.Hostname)
				}
				// The merged address set is what `vctl ssh --server <ip>` matches
				// on, so an ordering or dedup difference is a real divergence.
				if !reflect.DeepEqual(w.Addresses, g.Addresses) {
					t.Errorf("%s addresses: postgres=%v snapshot=%v", w.Hostname, w.Addresses, g.Addresses)
				}
				if w.JumpVia != g.JumpVia || w.User != g.User || w.DC != g.DC || w.Port != g.Port {
					t.Errorf("%s topology differs: postgres=%+v snapshot=%+v", w.Hostname, w.Server, g.Server)
				}
				if (w.AgentSeen == nil) != (g.AgentSeen == nil) {
					t.Errorf("%s agent heartbeat presence differs", w.Hostname)
				}
				if w.AgentVersion != g.AgentVersion {
					t.Errorf("%s agent version: postgres=%q snapshot=%q", w.Hostname, w.AgentVersion, g.AgentVersion)
				}
			}
		})
	}

	t.Run("Get", func(t *testing.T) {
		for _, h := range []string{"sre-srv-0047", "sre-bastion", "missing"} {
			wantSv, wantErr := live.Get(ctx, h)
			gotSv, gotErr := snapshot.Get(ctx, h)
			if (wantErr == nil) != (gotErr == nil) {
				t.Errorf("Get(%q) error mismatch: postgres=%v snapshot=%v", h, wantErr, gotErr)
				continue
			}
			if wantErr == nil && !reflect.DeepEqual(*wantSv, *gotSv) {
				t.Errorf("Get(%q): postgres=%+v snapshot=%+v", h, *wantSv, *gotSv)
			}
		}
	})
}

// seedBothReaders writes a fixture into the real database and returns it
// alongside a snapshot captured from it, so both readers answer from identical
// data.
func seedBothReaders(t *testing.T) (Reader, Reader) {
	t.Helper()
	dsn := os.Getenv("VCTL_TEST_DSN")
	if dsn == "" {
		t.Skip("VCTL_TEST_DSN not set; skipping differential test")
	}
	ctx := context.Background()
	st, err := store.OpenLocal(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(st.Close)
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	seenUp := time.Now().UTC()
	fixtures := []store.Server{
		{Hostname: "sre-srv-0047", IP: "198.51.100.47", Port: 22, User: "ubuntu", DC: "incheon", CARole: "sre-core", LastSeenUp: &seenUp},
		{Hostname: "sre-srv-0048", IP: "198.51.100.48", Port: 22, User: "ubuntu", DC: "incheon", CARole: "sre-core", JumpVia: "sre-bastion", LastSeenUp: &seenUp},
		{Hostname: "sre-bastion", IP: "198.51.100.10", Port: 22, User: "root", DC: "seoul-onprem", CARole: "sre-core", LastSeenUp: &seenUp},
	}
	for _, sv := range fixtures {
		// Remove first, and again on the way out. Upsert matches an existing host
		// by IP and keeps its hostname, so a row left behind by an earlier run —
		// or by this package, for a later one — silently captures the address and
		// the next test to claim it never gets its own row.
		if _, err := st.Delete(ctx, sv.Hostname); err != nil {
			t.Fatalf("clear %s: %v", sv.Hostname, err)
		}
		t.Cleanup(func() { _, _ = st.Delete(context.Background(), sv.Hostname) })
		if err := st.Upsert(ctx, sv); err != nil {
			t.Fatalf("seed %s: %v", sv.Hostname, err)
		}
	}
	if _, err := st.SetExtraIPs(ctx, "sre-srv-0047", []string{"198.51.100.147"}); err != nil {
		t.Fatalf("extra ips: %v", err)
	}
	if _, err := st.UpsertServerStatus(ctx, store.ServerStatus{
		Hostname: "sre-srv-0048", AgentVersion: "1.2.3", OS: "ubuntu",
		ObservedIPs: []string{"198.51.100.148"},
	}); err != nil {
		t.Fatalf("status: %v", err)
	}

	// Round-trip through the file, not just memory. Serialization is part of the
	// offline path — a snapshot is always read back from disk in production — and
	// it is where a nil-versus-empty slice distinction would quietly collapse.
	f := &FileStore{Path: filepath.Join(t.TempDir(), "inventory.json")}
	if err := f.Update(func(snap *Snapshot) error {
		return Capture(ctx, st, snap, time.Now())
	}); err != nil {
		t.Fatalf("capture: %v", err)
	}
	loaded, err := f.Load()
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	return st, NewMemory(loaded)
}

func name(sv *store.Server) string {
	if sv == nil {
		return ""
	}
	return sv.Hostname
}

func names(list []store.Server) []string {
	out := []string{}
	for _, s := range list {
		out = append(out, s.Hostname)
	}
	return out
}

func serverNames(list []store.Server) []string { return names(list) }
