package vaultc

import (
	"context"
	"errors"
	"slices"
	"testing"
)

// The KV half of the fixture verify-stack.sh writes: secrets the test identity
// may read under kv/teams/test, and one under kv/teams/private that it may not.
// The denied one is the point — `vctl kv search` is built on a 403 being a
// fact to report, and this is where that contract meets a real policy rather
// than a fake.

func TestKVListWithinPolicy(t *testing.T) {
	c := loggedIn(t)
	keys, err := c.ListKV(context.Background(), "kv/teams/test")
	if err != nil {
		t.Fatalf("ListKV: %v", err)
	}
	// beta is both a secret and a folder, and KV lists it as both.
	for _, want := range []string{"alpha", "beta", "beta/"} {
		if !slices.Contains(keys, want) {
			t.Errorf("keys = %v, want %q among them", keys, want)
		}
	}
}

func TestKVReadWithinPolicy(t *testing.T) {
	c := loggedIn(t)
	sec, err := c.ReadKVSecret(context.Background(), "kv/teams/test/alpha", 0)
	if err != nil {
		t.Fatalf("ReadKVSecret: %v", err)
	}
	if sec.Data["username"] != "alpha-user" {
		t.Errorf("Data = %v, want the fixture's username", sec.Data)
	}
	if sec.Version < 1 || sec.CreatedAt.IsZero() {
		t.Errorf("version metadata missing: version=%d created=%s", sec.Version, sec.CreatedAt)
	}
	if sec.CustomMetadata["owner"] != "fixture" {
		t.Errorf("CustomMetadata = %v, want the fixture's owner", sec.CustomMetadata)
	}
}

// Outside the policy the answer is a 403 that IsPermissionDenied recognises —
// on list and on read both. If either came back as some other error, a search
// would abort at the first private folder instead of reporting it.
func TestKVDeniedOutsidePolicy(t *testing.T) {
	c := loggedIn(t)
	ctx := context.Background()
	if _, err := c.ListKV(ctx, "kv/teams/private"); !IsPermissionDenied(err) {
		t.Errorf("ListKV(private) = %v, want permission denied", err)
	}
	if _, err := c.ReadKVSecret(ctx, "kv/teams/private/gamma", 0); !IsPermissionDenied(err) {
		t.Errorf("ReadKVSecret(private/gamma) = %v, want permission denied", err)
	}
}

// Missing is not forbidden, and not a transport failure: the sentinel is what
// lets the CLI say "check the path" rather than print a 404.
func TestKVNotFoundIsItsOwnAnswer(t *testing.T) {
	c := loggedIn(t)
	ctx := context.Background()
	if _, err := c.ReadKVSecret(ctx, "kv/teams/test/absent", 0); !errors.Is(err, ErrKVNotFound) {
		t.Errorf("read of a missing secret = %v, want ErrKVNotFound", err)
	}
	if _, err := c.ListKV(ctx, "kv/teams/test/absent"); !errors.Is(err, ErrKVNotFound) {
		t.Errorf("list of a missing folder = %v, want ErrKVNotFound", err)
	}
}
