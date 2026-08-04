package vaultc

import "testing"

// KV v2 stores under <mount>/data/<rest>. Callers pass the logical path an
// operator types, and inserting the segment here is what keeps that detail out
// of every call site.
func TestKVDataPathInsertsTheDataSegment(t *testing.T) {
	for in, want := range map[string]string{
		"kv/teams/sre/openstack/farm-a": "kv/data/teams/sre/openstack/farm-a",
		"/kv/teams/sre/x":               "kv/data/teams/sre/x",
		// Already addressed at the data segment: left alone rather than doubled.
		"kv/data/teams/sre/x": "kv/data/teams/sre/x",
		// No path under the mount at all — nothing to rewrite.
		"kv": "kv",
	} {
		if got := kvDataPath(in); got != want {
			t.Errorf("kvDataPath(%q) = %q, want %q", in, got, want)
		}
	}
}
