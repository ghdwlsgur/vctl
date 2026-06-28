// Package auditredact removes common credential forms from process arguments
// before they enter the central audit database.
package auditredact

import "regexp"

const replacement = "$1[REDACTED]"

var patterns = []*regexp.Regexp{
	// --password value, --token=value, --client-secret value, etc.
	regexp.MustCompile(`(?i)(--(?:password|passwd|token|secret|client-secret|api-key|access-key)(?:=|\s+))\S+`),
	// Authorization headers passed to curl and similar clients.
	regexp.MustCompile(`(?i)((?:authorization|proxy-authorization):\s*(?:bearer|basic)\s+)\S+`),
	// Common secret-bearing environment assignments.
	regexp.MustCompile(`(?i)(\b(?:password|passwd|token|secret|client_secret|api_key|access_key)=)\S+`),
	// Kubernetes secret literals contain the secret after the first equals sign.
	regexp.MustCompile(`(?i)(--from-literal(?:=|\s+)\S+=)\S+`),
	// URI userinfo: preserve scheme and username, redact only the password.
	regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://[^\s:/@]+:)[^\s@]+(@)`),
}

// Arguments returns args with recognized credential values replaced. It is a
// defense-in-depth filter; callers must still restrict access to audit rows.
func Arguments(args string) string {
	for i, pattern := range patterns {
		if i == len(patterns)-1 {
			args = pattern.ReplaceAllString(args, "$1[REDACTED]$2")
			continue
		}
		args = pattern.ReplaceAllString(args, replacement)
	}
	return args
}
