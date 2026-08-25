package config

import _ "embed"

// SRERootCA is the private root CA for *.sre.local.
// It is embedded so Vault and Postgres TLS can be verified without local CA setup.
//
//go:embed innogrid-sre-root-ca.crt
var SRERootCA []byte

// SRERootCAName is the filename the embedded CA is installed under in a
// system trust store. It lives next to the bytes it names: both are the
// org-specific compiled surface a fork replaces together, and the name was a
// constant in the CLI where nothing marked it as that surface.
const SRERootCAName = "innogrid-sre-root-ca.crt"
