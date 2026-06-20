package config

import _ "embed"

// SRERootCA is the private root CA for *.sre.local.
// It is embedded so Vault and Postgres TLS can be verified without local CA setup.
//
//go:embed innogrid-sre-root-ca.crt
var SRERootCA []byte
