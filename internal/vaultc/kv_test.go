package vaultc

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	vault "github.com/hashicorp/vault/api"
)

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

// LIST lives at <mount>/metadata/<rest>. Same idea as the data segment, with
// the two edges the data helper never meets: the bare mount lists the root,
// and a path someone already typed at data/ is moved, not doubled.
func TestKVMetadataPathAddressesTheMetadataEndpoint(t *testing.T) {
	for in, want := range map[string]string{
		"kv/teams/sre":          "kv/metadata/teams/sre",
		"kv/teams/sre/":         "kv/metadata/teams/sre",
		"/kv/teams/sre":         "kv/metadata/teams/sre",
		"kv":                    "kv/metadata",
		"kv/":                   "kv/metadata",
		"kv/data":               "kv/metadata",
		"kv/data/teams/sre":     "kv/metadata/teams/sre",
		"kv/metadata/teams/sre": "kv/metadata/teams/sre",
	} {
		if got := kvMetadataPath(in); got != want {
			t.Errorf("kvMetadataPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseKVSecretReadsTheV2Envelope(t *testing.T) {
	sec := &vault.Secret{Data: map[string]interface{}{
		"data": map[string]interface{}{
			"token":    "token-field-value",
			"username": "someone",
			"retries":  json.Number("3"),
			"tags":     []interface{}{"a"},
		},
		"metadata": map[string]interface{}{
			"version":         json.Number("4"),
			"created_time":    "2026-06-19T02:03:04.5Z",
			"deletion_time":   "",
			"destroyed":       false,
			"custom_metadata": map[string]interface{}{"owner": "sre"},
		},
	}}
	got := parseKVSecret("kv/teams/sre/x", sec)

	if got.Path != "kv/teams/sre/x" || got.Version != 4 {
		t.Fatalf("path/version = %q/%d, want kv/teams/sre/x/4", got.Path, got.Version)
	}
	if want := time.Date(2026, 6, 19, 2, 3, 4, 500_000_000, time.UTC); !got.CreatedAt.Equal(want) {
		t.Errorf("CreatedAt = %s, want %s", got.CreatedAt, want)
	}
	if !got.DeletedAt.IsZero() || got.Destroyed {
		t.Errorf("a live version reads as deleted: %+v", got)
	}
	if got.Data["token"] != "token-field-value" || got.Data["username"] != "someone" || len(got.Data) != 2 {
		t.Errorf("Data = %v, want exactly the two string fields", got.Data)
	}
	// Named and sorted, never rendered.
	if fmt.Sprint(got.NonString) != "[retries tags]" {
		t.Errorf("NonString = %v, want [retries tags]", got.NonString)
	}
	if got.CustomMetadata["owner"] != "sre" {
		t.Errorf("CustomMetadata = %v, want owner=sre", got.CustomMetadata)
	}
}

// A soft-deleted version comes back with data null beside its metadata. It
// must read as deleted, not as a secret with no fields.
func TestParseKVSecretReportsADeletedVersion(t *testing.T) {
	sec := &vault.Secret{Data: map[string]interface{}{
		"data": nil,
		"metadata": map[string]interface{}{
			"version":       json.Number("2"),
			"created_time":  "2026-01-01T00:00:00Z",
			"deletion_time": "2026-02-01T00:00:00Z",
			"destroyed":     false,
		},
	}}
	got := parseKVSecret("kv/x/y", sec)
	if len(got.Data) != 0 || got.DeletedAt.IsZero() || got.Version != 2 {
		t.Fatalf("deleted version parsed as %+v", got)
	}
}

func TestParseKVSecretFallsBackToTheFlatV1Shape(t *testing.T) {
	sec := &vault.Secret{Data: map[string]interface{}{"username": "someone", "count": json.Number("1")}}
	got := parseKVSecret("secret/x", sec)
	if got.Data["username"] != "someone" || got.Version != 0 || fmt.Sprint(got.NonString) != "[count]" {
		t.Fatalf("v1 secret parsed as %+v", got)
	}
}

// The walk skips exactly what Vault refused. A 404, a 500 or a dead network
// must not be mistaken for a policy — each of those means something else.
func TestIsPermissionDeniedRecognisesOnlyA403(t *testing.T) {
	forbidden := &vault.ResponseError{StatusCode: http.StatusForbidden}
	if !IsPermissionDenied(forbidden) {
		t.Error("a bare 403 was not recognised")
	}
	if !IsPermissionDenied(fmt.Errorf("kv/x: %w", forbidden)) {
		t.Error("a wrapped 403 was not recognised — callers wrap with the path")
	}
	for _, err := range []error{
		&vault.ResponseError{StatusCode: http.StatusNotFound},
		&vault.ResponseError{StatusCode: http.StatusInternalServerError},
		errors.New("dial tcp: connection refused"),
		ErrKVNotFound,
		nil,
	} {
		if IsPermissionDenied(err) {
			t.Errorf("%v read as permission denied", err)
		}
	}
}
