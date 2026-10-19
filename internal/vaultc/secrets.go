package vaultc

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"regexp"
	"strings"
	"time"

	vault "github.com/hashicorp/vault/api"
)

var nodeAccessHostRE = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
var novaInstanceUUIDRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// SignVMAgentCSR issues only the requested VM's public key. Unlike issuing a
// certificate with a server-generated key, this keeps every VM private key on
// that VM and makes renewal possible without a long-lived guest Vault secret.
func (c *Client) SignVMAgentCSR(ctx context.Context, instanceUUID, csrPEM string) ([]byte, error) {
	if !novaInstanceUUIDRE.MatchString(instanceUUID) {
		return nil, fmt.Errorf("invalid Nova instance UUID %q", instanceUUID)
	}
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("invalid VM certificate signing request")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse VM certificate signing request: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("verify VM certificate signing request: %w", err)
	}
	commonName := instanceUUID + ".vm.sre.local"
	uriSAN := "spiffe://vctl.local/vm/" + instanceUUID
	issued, err := c.writePath(ctx, "pki_sre_int/sign/vctl-vm-agent", map[string]interface{}{
		"csr": csrPEM, "common_name": commonName, "uri_sans": uriSAN, "ttl": "720h", "format": "pem",
	})
	if err != nil {
		return nil, fmt.Errorf("sign VM node-access certificate: %w", err)
	}
	certificate, _ := issued.Data["certificate"].(string)
	if certificate == "" {
		return nil, fmt.Errorf("PKI returned an incomplete VM node-access certificate")
	}
	chain, _ := issued.Data["ca_chain"].([]interface{})
	certPEM := []byte(certificate + "\n")
	for _, item := range chain {
		if ca, ok := item.(string); ok {
			certPEM = append(certPEM, []byte(ca+"\n")...)
		}
	}
	leafBlock, _ := pem.Decode(certPEM)
	if leafBlock == nil || leafBlock.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("PKI returned an invalid VM certificate")
	}
	leaf, err := x509.ParseCertificate(leafBlock.Bytes)
	if err != nil || leaf.Subject.CommonName != commonName || len(leaf.URIs) != 1 || leaf.URIs[0].String() != uriSAN {
		return nil, fmt.Errorf("PKI returned a certificate with the wrong VM identity")
	}
	if !bytes.Equal(csr.RawSubjectPublicKeyInfo, leaf.RawSubjectPublicKeyInfo) {
		return nil, fmt.Errorf("PKI returned a certificate for a different public key")
	}
	return certPEM, nil
}

// NodeAccessIdentity contains one node's scoped renewal credential and the
// first short-lived mTLS identity. The private key is returned only to the
// enrolling operator process and is never stored in Vault.
type NodeAccessIdentity struct {
	RoleID, SecretID string
	CertificatePEM   []byte
	PrivateKeyPEM    []byte
}

// EnsureNodeAccessIdentity creates the isolated PKI role and AppRole needed by
// one host, then issues its initial certificate. Calling it again is safe; a
// fresh secret-id and certificate are generated each time.
func (c *Client) EnsureNodeAccessIdentity(ctx context.Context, hostname, approleMount string) (NodeAccessIdentity, error) {
	if !nodeAccessHostRE.MatchString(hostname) {
		return NodeAccessIdentity{}, fmt.Errorf("invalid node-access inventory hostname %q", hostname)
	}
	if approleMount == "" {
		return NodeAccessIdentity{}, fmt.Errorf("AppRole mount is required")
	}
	role := "vctl-node-access-" + hostname
	policy := fmt.Sprintf("path \"pki_sre_int/issue/%s\" { capabilities = [\"update\"] }", role)
	if err := c.api.Sys().PutPolicyWithContext(ctx, role, policy); err != nil {
		return NodeAccessIdentity{}, fmt.Errorf("write node-access policy: %w", err)
	}
	_, err := c.api.Logical().WriteWithContext(ctx, "pki_sre_int/roles/"+role, map[string]interface{}{
		"allowed_domains": []string{hostname + ".sre.local"}, "allowed_uri_sans": []string{"spiffe://vctl.local/node/" + hostname},
		"allow_bare_domains": true, "allow_subdomains": false, "allow_glob_domains": false,
		"allow_any_name": false, "allow_ip_sans": false, "allow_localhost": false,
		"allow_wildcard_certificates": false, "client_flag": true, "server_flag": false,
		"key_type": "ec", "key_bits": 256, "ext_key_usage": []string{"ClientAuth"}, "ttl": "720h", "max_ttl": "720h",
	})
	if err != nil {
		return NodeAccessIdentity{}, fmt.Errorf("write node-access PKI role: %w", err)
	}
	_, err = c.api.Logical().WriteWithContext(ctx, "auth/"+approleMount+"/role/"+role, map[string]interface{}{
		"token_policies": []string{role}, "token_ttl": 3600, "token_max_ttl": 3600,
		"token_type": "service", "secret_id_ttl": 0, "secret_id_num_uses": 0,
	})
	if err != nil {
		return NodeAccessIdentity{}, fmt.Errorf("write node-access AppRole: %w", err)
	}
	roleID, err := c.AppRoleRoleID(ctx, approleMount, role)
	if err != nil {
		return NodeAccessIdentity{}, fmt.Errorf("read node-access AppRole id: %w", err)
	}
	secretID, _, err := c.GenerateSecretIDWithAccessor(ctx, approleMount, role)
	if err != nil {
		return NodeAccessIdentity{}, fmt.Errorf("generate node-access AppRole secret: %w", err)
	}
	issued, err := c.writePath(ctx, "pki_sre_int/issue/"+role, map[string]interface{}{
		"common_name": hostname + ".sre.local", "uri_sans": "spiffe://vctl.local/node/" + hostname, "ttl": "720h", "format": "pem",
	})
	if err != nil {
		return NodeAccessIdentity{}, fmt.Errorf("issue node-access certificate: %w", err)
	}
	certificate, _ := issued.Data["certificate"].(string)
	privateKey, _ := issued.Data["private_key"].(string)
	if certificate == "" || privateKey == "" {
		return NodeAccessIdentity{}, fmt.Errorf("PKI returned an incomplete node-access certificate")
	}
	chain, _ := issued.Data["ca_chain"].([]interface{})
	var certPEM []byte
	certPEM = append(certPEM, []byte(certificate+"\n")...)
	for _, item := range chain {
		if ca, ok := item.(string); ok {
			certPEM = append(certPEM, []byte(ca+"\n")...)
		}
	}
	if _, err := tls.X509KeyPair(certPEM, []byte(privateKey)); err != nil {
		return NodeAccessIdentity{}, fmt.Errorf("validate node-access certificate: %w", err)
	}
	return NodeAccessIdentity{RoleID: roleID, SecretID: secretID, CertificatePEM: certPEM, PrivateKeyPEM: []byte(privateKey)}, nil
}

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
	sid, _, err := c.GenerateSecretIDWithAccessor(ctx, mount, role)
	return sid, err
}

// GenerateSecretIDWithAccessor issues a fresh secret_id and also returns its
// accessor — the handle an operator stores so the credential can later be
// revoked without ever writing the secret itself anywhere else.
func (c *Client) GenerateSecretIDWithAccessor(ctx context.Context, mount, role string) (secretID, accessor string, err error) {
	p := fmt.Sprintf("auth/%s/role/%s/secret-id", mount, role)
	sec, err := c.writePath(ctx, p, nil)
	if err != nil {
		return "", "", err
	}
	if secretID, err = reqString(sec, p, "secret_id"); err != nil {
		return "", "", err
	}
	if accessor, err = reqString(sec, p, "secret_id_accessor"); err != nil {
		return "", "", err
	}
	return secretID, accessor, nil
}

var (
	appRoleNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)
	secretIDAccRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

// DestroySecretIDAccessor revokes one secret_id by its accessor. The secret_ids
// minted for hosts have no TTL and no use limit, so one that has been replaced
// stays a working credential until somebody destroys it. Role and accessor are
// often read back from a host, so both are checked before they reach the path.
func (c *Client) DestroySecretIDAccessor(ctx context.Context, mount, role, accessor string) error {
	if !appRoleNameRE.MatchString(role) {
		return fmt.Errorf("invalid AppRole name %q", role)
	}
	if !secretIDAccRE.MatchString(accessor) {
		return fmt.Errorf("invalid secret_id accessor %q", accessor)
	}
	// Not writePath: destroy answers 204 with no body, which writePath reads as
	// a failure even though the credential is gone.
	p := fmt.Sprintf("auth/%s/role/%s/secret-id-accessor/destroy", mount, role)
	if _, err := c.api.Logical().WriteWithContext(ctx, p, map[string]any{"secret_id_accessor": accessor}); err != nil {
		return fmt.Errorf("%s: %w", p, err)
	}
	return nil
}

// KV reads and listing live in kv.go.
