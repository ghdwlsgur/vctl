package vaultc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	vault "github.com/hashicorp/vault/api"
)

// ErrKVNotFound reports that Vault has nothing at the path: no secret to read,
// no children to list. Vault answers 404 for both and the api client turns
// that into a nil secret, so every caller was about to inspect a nil for the
// same reason. One sentinel, and the CLI can tell "not there" from "not
// allowed" — which look alike from a distance and mean a typo and a policy.
var ErrKVNotFound = errors.New("not found")

// IsPermissionDenied reports whether err is Vault refusing the request (403).
//
// A recursive search needs the distinction: a subtree the token may not list is
// a fact to report, not a reason to abandon the rest of the walk.
func IsPermissionDenied(err error) bool {
	var re *vault.ResponseError
	return errors.As(err, &re) && re.StatusCode == http.StatusForbidden
}

// KVSecret is one KV secret as an operator reads it: the string fields, and the
// version metadata that says whether what they are looking at is current.
type KVSecret struct {
	Path string
	// Data holds the string fields. Anything else is named in NonString rather
	// than stringified — see ReadKV for why.
	Data map[string]string
	// NonString lists the keys whose values are not strings, sorted, so a
	// listing can say a field exists without inventing a rendering for it.
	NonString []string
	Version   int
	CreatedAt time.Time
	// DeletedAt is set when this version was soft-deleted and Destroyed when its
	// data was erased. Either way Data is empty, and the caller should say which
	// rather than report an empty secret.
	DeletedAt time.Time
	Destroyed bool
	// CustomMetadata is the operator-set annotation on the secret (owner,
	// rotation note). Not secret, and shown beside the keys.
	CustomMetadata map[string]string
}

// ReadKVSecret reads one KV secret with its version metadata. version 0 is the
// current version; any other number is that version.
func (c *Client) ReadKVSecret(ctx context.Context, path string, version int) (KVSecret, error) {
	var params map[string][]string
	if version > 0 {
		params = map[string][]string{"version": {fmt.Sprint(version)}}
	}
	sec, err := c.api.Logical().ReadWithDataWithContext(ctx, kvDataPath(path), params)
	if err != nil {
		return KVSecret{}, fmt.Errorf("%s: %w", path, err)
	}
	if sec == nil || sec.Data == nil {
		return KVSecret{}, fmt.Errorf("%s: %w", path, ErrKVNotFound)
	}
	return parseKVSecret(path, sec), nil
}

// parseKVSecret reads the KV v2 envelope — the fields one level down under
// "data", the version metadata beside them — and falls back to the flat v1
// shape when there is no envelope.
//
// A soft-deleted version arrives with "data" present and null: Vault answers
// 404 with a body, and the api client returns that body as a secret. So the
// envelope is recognised by both keys being present, not by "data" holding a
// map.
func parseKVSecret(path string, sec *vault.Secret) KVSecret {
	out := KVSecret{Path: path, Data: map[string]string{}}
	fields := sec.Data
	_, hasData := sec.Data["data"]
	meta, hasMeta := sec.Data["metadata"].(map[string]interface{})
	if hasData && hasMeta {
		out.Version = jsonInt(meta["version"])
		out.CreatedAt = rfc3339(meta["created_time"])
		out.DeletedAt = rfc3339(meta["deletion_time"])
		out.Destroyed, _ = meta["destroyed"].(bool)
		if cm, ok := meta["custom_metadata"].(map[string]interface{}); ok && len(cm) > 0 {
			out.CustomMetadata = make(map[string]string, len(cm))
			for k, v := range cm {
				out.CustomMetadata[k] = fmt.Sprint(v)
			}
		}
		fields, _ = sec.Data["data"].(map[string]interface{})
	}
	for k, v := range fields {
		if s, ok := v.(string); ok {
			out.Data[k] = s
			continue
		}
		out.NonString = append(out.NonString, k)
	}
	sort.Strings(out.NonString)
	return out
}

// jsonInt reads a number the api client decoded with UseNumber, tolerating the
// other shapes a hand-built secret might carry.
func jsonInt(v interface{}) int {
	switch n := v.(type) {
	case json.Number:
		i, _ := n.Int64()
		return int(i)
	case float64:
		return int(n)
	case int:
		return n
	}
	return 0
}

// rfc3339 parses Vault's timestamps; the empty string KV uses for "never
// deleted" becomes the zero time.
func rfc3339(v interface{}) time.Time {
	s, _ := v.(string)
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

// ListKV returns the entries directly under path: secret names, and folders
// with a trailing "/". KV lets a secret and a folder share a name, and then
// both appear, as Vault lists them.
func (c *Client) ListKV(ctx context.Context, path string) ([]string, error) {
	sec, err := c.api.Logical().ListWithContext(ctx, kvMetadataPath(path))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if sec == nil || sec.Data == nil {
		return nil, fmt.Errorf("%s: %w", path, ErrKVNotFound)
	}
	raw, _ := sec.Data["keys"].([]interface{})
	keys := make([]string, 0, len(raw))
	for _, k := range raw {
		if s, ok := k.(string); ok && s != "" {
			keys = append(keys, s)
		}
	}
	sort.Strings(keys)
	return keys, nil
}

// ReadKV reads a KV secret and returns its string fields — the current
// version, and only what a credential consumer can use.
//
// Anything that is not a string is dropped rather than stringified: a caller
// asking for credentials should get what was stored or nothing, not a
// rendering of a nested structure. One parser for both readers, so a deleted
// version or a v1 mount reads the same here as in `vctl kv get`.
func (c *Client) ReadKV(ctx context.Context, path string) (map[string]string, error) {
	sec, err := c.ReadKVSecret(ctx, path, 0)
	if err != nil {
		return nil, err
	}
	if len(sec.Data) == 0 {
		// Deliberately says nothing about what was there. This function's
		// callers handle credentials, and an error string is the easiest place
		// for one to escape into a log.
		return nil, fmt.Errorf("%s: no string fields", path)
	}
	return sec.Data, nil
}

// kvDataPath turns kv/teams/sre/x into kv/data/teams/sre/x, and leaves a path
// that already names the data segment alone.
func kvDataPath(path string) string {
	p := strings.TrimPrefix(path, "/")
	mount, rest, ok := strings.Cut(p, "/")
	if !ok || strings.HasPrefix(rest, "data/") {
		return p
	}
	return mount + "/data/" + rest
}

// kvMetadataPath is kvDataPath's sibling for the metadata endpoint, where KV v2
// answers LIST. The mount alone becomes <mount>/metadata — a listing of the
// root — and a path already at data/ is moved over rather than doubled.
func kvMetadataPath(path string) string {
	p := strings.Trim(path, "/")
	mount, rest, ok := strings.Cut(p, "/")
	switch {
	case !ok:
		return mount + "/metadata"
	case rest == "metadata", strings.HasPrefix(rest, "metadata/"):
		return p
	case rest == "data":
		return mount + "/metadata"
	case strings.HasPrefix(rest, "data/"):
		return mount + "/metadata/" + strings.TrimPrefix(rest, "data/")
	}
	return mount + "/metadata/" + rest
}
