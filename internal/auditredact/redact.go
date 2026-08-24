// Package auditredact removes common credential forms from process arguments
// before they enter the central audit database.
package auditredact

import "regexp"

// Each pattern carries its own replacement template. Most only re-emit their
// captured prefix, but the URI userinfo pattern must also put back the "@" it
// captured. When the template was chosen by position — "the last pattern is
// the special one" — appending a new pattern handed the URI template's job to
// the newcomer and dropped the "@" from every redacted URI. Keeping the
// template beside its pattern is what makes appending safe.
var rules = []struct {
	re   *regexp.Regexp
	repl string
}{
	// --password value, --token=value, --client-secret value, etc.
	{regexp.MustCompile(`(?i)(--(?:password|passwd|token|secret|client-secret|api-key|access-key)(?:=|\s+))\S+`),
		"$1[REDACTED]"},
	// Authorization headers passed to curl and similar clients.
	{regexp.MustCompile(`(?i)((?:authorization|proxy-authorization):\s*(?:bearer|basic)\s+)\S+`),
		"$1[REDACTED]"},
	// Common secret-bearing environment assignments.
	{regexp.MustCompile(`(?i)(\b(?:password|passwd|token|secret|client_secret|api_key|access_key)=)\S+`),
		"$1[REDACTED]"},
	// Kubernetes secret literals contain the secret after the first equals sign.
	{regexp.MustCompile(`(?i)(--from-literal(?:=|\s+)\S+=)\S+`),
		"$1[REDACTED]"},
	// URI userinfo: preserve scheme and username, redact only the password.
	{regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://[^\s:/@]+:)[^\s@]+(@)`),
		"$1[REDACTED]$2"},
}

// Arguments returns args with recognized credential values replaced. It is a
// defense-in-depth filter; callers must still restrict access to audit rows.
func Arguments(args string) string {
	for _, r := range rules {
		args = r.re.ReplaceAllString(args, r.repl)
	}
	return args
}
