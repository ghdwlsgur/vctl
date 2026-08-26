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
	// Secret-bearing environment assignments. The variable name ends in a
	// sensitive word but usually carries a prefix — VAULT_TOKEN, PGPASSWORD,
	// AWS_SECRET_ACCESS_KEY, MYSQL_PWD — and the previous \b anchor never matched
	// across the underscore, so every prefixed secret went to the audit log in
	// the clear. Match a whole [A-Za-z0-9_] name that ends in the sensitive word,
	// anchored to a word start so a substring inside another token is left alone.
	{regexp.MustCompile(`(?i)((?:^|\s)[a-z0-9_]*(?:password|passwd|pwd|token|secret|api_key|access_key)=)\S+`),
		"$1[REDACTED]"},
	// Kubernetes secret literals contain the secret after the first equals sign.
	{regexp.MustCompile(`(?i)(--from-literal(?:=|\s+)\S+=)\S+`),
		"$1[REDACTED]"},
	// `vault login <token>`: the token is the positional argument after `login`.
	// Only a value that does not start with '-' is redacted, so `vault login
	// -method=oidc` keeps its flag while `vault login hvs...` does not keep its
	// token.
	{regexp.MustCompile(`(?i)(\bvault\s+login\s+)([^\s-]\S*)`),
		"$1[REDACTED]"},
	// curl -u user:password (and --user). The username is kept, the password after
	// the colon is not.
	{regexp.MustCompile(`(?i)((?:-u|--user)\s+[^\s:]+:)\S+`),
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
