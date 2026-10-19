package nodeaccess

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/ghdwlsgur/vctl/internal/config"
)

// ParseKeystoneCA accepts the certificate authority a farm's Keystone is
// issued from, and nothing else.
//
// Kolla generates its own CA when a farm turns on internal TLS
// (infra-3x5-epoxy: CN=InnogridCA), so a farm's Keystone is often signed by a
// CA neither the system pool nor the SRE root contains. Registering that CA is
// what lets the gateway verify the farm before it sends Nova's service token.
// Only CA certificates are accepted: a pinned leaf would keep verifying after
// the farm moved to another CA, and any other PEM block — a private key
// pasted by mistake above all — must never be stored.
func ParseKeystoneCA(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("only CERTIFICATE blocks are accepted, found %q", block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
		if !cert.BasicConstraintsValid || !cert.IsCA {
			return nil, fmt.Errorf("%q is not a CA certificate; register the CA that issued Keystone's certificate", cert.Subject.String())
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no PEM certificate found")
	}
	return certs, nil
}

// keystoneRoots is what a farm's Keystone is verified against: the system
// pool, the SRE root, and the farm's registered CA when it has one.
func keystoneRoots(farmCA []byte) (*x509.CertPool, error) {
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if !roots.AppendCertsFromPEM(config.SRERootCA) && len(config.SRERootCA) > 0 {
		return nil, fmt.Errorf("embedded SRE certificate authority is invalid")
	}
	if len(farmCA) > 0 {
		certs, err := ParseKeystoneCA(farmCA)
		if err != nil {
			return nil, fmt.Errorf("registered Keystone CA: %w", err)
		}
		for _, c := range certs {
			roots.AddCert(c)
		}
	}
	return roots, nil
}
