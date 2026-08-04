package vaultc

import (
	"context"
	"fmt"
	"strings"
	"time"

	vault "github.com/hashicorp/vault/api"
)

// readPath/writePath wrap Logical().Read/Write with uniform handling: a
// path-prefixed transport error and an "empty response" guard, so callers skip
// the repeated nil/Data checks. The returned secret has non-nil Data.
func (c *Client) readPath(ctx context.Context, path string) (*vault.Secret, error) {
	sec, err := c.api.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if sec == nil || sec.Data == nil {
		return nil, fmt.Errorf("%s: empty response", path)
	}
	return sec, nil
}

func (c *Client) writePath(ctx context.Context, path string, payload map[string]interface{}) (*vault.Secret, error) {
	sec, err := c.api.Logical().WriteWithContext(ctx, path, payload)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if sec == nil || sec.Data == nil {
		return nil, fmt.Errorf("%s: empty response", path)
	}
	return sec, nil
}

// reqString extracts a required non-empty string field, erroring with the path.
func reqString(sec *vault.Secret, path, key string) (string, error) {
	v, _ := sec.Data[key].(string)
	if v == "" {
		return "", fmt.Errorf("%s: missing %s", path, key)
	}
	return v, nil
}

// SignSSH signs a public key through ssh/sign/<role> and returns an OpenSSH cert.
// The private key remains client-side and is never sent to Vault.
func (c *Client) SignSSH(ctx context.Context, role, publicKey string, principals []string, ttl string, extensions []string) (string, error) {
	payload := map[string]interface{}{
		"public_key":       publicKey,
		"valid_principals": strings.Join(principals, ","),
		"ttl":              ttl,
	}
	if len(extensions) > 0 {
		ext := make(map[string]interface{}, len(extensions))
		for _, name := range extensions {
			ext[name] = ""
		}
		payload["extensions"] = ext
	}
	path := "ssh/sign/" + role
	sec, err := c.writePath(ctx, path, payload)
	if err != nil {
		return "", err
	}
	return reqString(sec, path, "signed_key")
}

// SSHCAPublicKey returns the Vault SSH CA public key (ssh/config/ca). Hosts trust
// this key via TrustedUserCAKeys so they accept vctl's signed certificates.
func (c *Client) SSHCAPublicKey(ctx context.Context) (string, error) {
	sec, err := c.readPath(ctx, "ssh/config/ca")
	if err != nil {
		return "", err
	}
	pub, err := reqString(sec, "ssh/config/ca", "public_key")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(pub), nil
}

// DBLease is a dynamic Postgres credential together with the lease that governs
// it. The lease is returned, not discarded, because issuing a credential is the
// expensive half of this operation: Vault runs a CREATE ROLE against Postgres
// and schedules a DROP ROLE for expiry. Holding the lease id lets a caller renew
// what it already has instead of paying that again.
type DBLease struct {
	User      string
	Pass      string
	ID        string // lease id, for RenewLease
	TTL       time.Duration
	Renewable bool
}

// DBCreds requests short-lived Postgres credentials from database/creds/<role>.
func (c *Client) DBCreds(ctx context.Context, role string) (DBLease, error) {
	path := "database/creds/" + role
	sec, err := c.readPath(ctx, path)
	if err != nil {
		return DBLease{}, err
	}
	l := DBLease{
		ID:        sec.LeaseID,
		TTL:       time.Duration(sec.LeaseDuration) * time.Second,
		Renewable: sec.Renewable,
	}
	if l.User, err = reqString(sec, path, "username"); err != nil {
		return DBLease{}, err
	}
	if l.Pass, err = reqString(sec, path, "password"); err != nil {
		return DBLease{}, err
	}
	return l, nil
}

// RenewLease extends an existing lease and reports the TTL Vault granted.
//
// The granted TTL is not the requested one. Vault clamps it to whatever remains
// of the secret's max_ttl, so a renewal near that ceiling returns a short TTL
// and eventually stops extending at all. Callers must act on the returned value
// rather than assuming the increment was honoured — treating a clamped renewal
// as a full one is how a credential expires while still in use.
func (c *Client) RenewLease(ctx context.Context, leaseID string, increment time.Duration) (ttl time.Duration, renewable bool, err error) {
	const path = "sys/leases/renew"
	// Not writePath: a renewal's payload is carried in the secret's lease fields
	// and Data is legitimately nil, which writePath rejects as an empty response.
	sec, err := c.api.Logical().WriteWithContext(ctx, path, map[string]interface{}{
		"lease_id":  leaseID,
		"increment": int(increment.Seconds()),
	})
	if err != nil {
		return 0, false, fmt.Errorf("%s: %w", path, err)
	}
	if sec == nil {
		return 0, false, fmt.Errorf("%s: empty response", path)
	}
	return time.Duration(sec.LeaseDuration) * time.Second, sec.Renewable, nil
}

// AppRoleRoleID reads the role_id for an approle role (not a secret).
func (c *Client) AppRoleRoleID(ctx context.Context, mount, role string) (string, error) {
	p := fmt.Sprintf("auth/%s/role/%s/role-id", mount, role)
	sec, err := c.readPath(ctx, p)
	if err != nil {
		return "", err
	}
	return reqString(sec, p, "role_id")
}

// GenerateSecretID issues a fresh secret_id for an approle role.
func (c *Client) GenerateSecretID(ctx context.Context, mount, role string) (string, error) {
	p := fmt.Sprintf("auth/%s/role/%s/secret-id", mount, role)
	sec, err := c.writePath(ctx, p, nil)
	if err != nil {
		return "", err
	}
	return reqString(sec, p, "secret_id")
}

// ReadKV reads a KV v2 secret and returns its string fields.
//
// The path is the logical one an operator types — kv/teams/sre/x — and the
// mount's data segment is inserted here, so callers do not have to know that
// KV v2 stores under kv/data/.
//
// Only string fields are returned. Anything else in the secret is dropped
// rather than stringified: a caller asking for credentials should get what was
// stored or nothing, not a rendering of a nested structure.
func (c *Client) ReadKV(ctx context.Context, path string) (map[string]string, error) {
	sec, err := c.readPath(ctx, kvDataPath(path))
	if err != nil {
		return nil, err
	}
	// KV v2 nests the payload one level down; v1 does not.
	data := sec.Data
	if inner, ok := sec.Data["data"].(map[string]interface{}); ok {
		data = inner
	}
	out := make(map[string]string, len(data))
	for k, v := range data {
		if s, ok := v.(string); ok {
			out[k] = s
		}
	}
	if len(out) == 0 {
		// Deliberately says nothing about what was there. This function's
		// callers handle credentials, and an error string is the easiest place
		// for one to escape into a log.
		return nil, fmt.Errorf("%s: no string fields", path)
	}
	return out, nil
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
