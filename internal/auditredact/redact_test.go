package auditredact

import "testing"

func TestArguments(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"long flag space", `login --password hunter2 --user sre`, `login --password [REDACTED] --user sre`},
		{"long flag equals", `curl --token=abc123 /health`, `curl --token=[REDACTED] /health`},
		{"authorization", `curl -H Authorization: Bearer abc123 https://api`, `curl -H Authorization: Bearer [REDACTED] https://api`},
		{"environment", `env API_KEY=abc TOKEN=def command`, `env API_KEY=[REDACTED] TOKEN=[REDACTED] command`},
		// Prefixed variable names are the common case and exactly what the old \b
		// anchor let through — the boundary never held across the underscore.
		{"prefixed env vault", `env VAULT_TOKEN=hvs.abc vault kv get x`, `env VAULT_TOKEN=[REDACTED] vault kv get x`},
		{"prefixed env pg", `PGPASSWORD=s3cret psql -h db`, `PGPASSWORD=[REDACTED] psql -h db`},
		{"prefixed env aws", `env AWS_SECRET_ACCESS_KEY=zzz aws s3 ls`, `env AWS_SECRET_ACCESS_KEY=[REDACTED] aws s3 ls`},
		{"prefixed env mysql pwd", `MYSQL_PWD=hunter2 mysql`, `MYSQL_PWD=[REDACTED] mysql`},
		// A name that only contains a sensitive word as a substring, not a suffix
		// ending at '=', is not a credential and is left alone.
		{"substring not suffix", `env TOKENIZER=on run`, `env TOKENIZER=on run`},
		// The fixture deliberately does NOT wear Vault's real "hvs." prefix —
		// secret scanners pattern-match it, and a redaction test is the one
		// place secret-shaped strings must not live. The rule is positional
		// (anything after `vault login` not starting with '-'), so a neutral
		// stand-in exercises it identically.
		{"vault login token", `vault login dummy.TESTTOKEN`, `vault login [REDACTED]`},
		{"vault login flag kept", `vault login -method=oidc`, `vault login -method=oidc`},
		{"curl basic user pass", `curl -u admin:s3cret https://api`, `curl -u admin:[REDACTED] https://api`},
		{"kubernetes literal", `kubectl create secret generic x --from-literal=password=abc`, `kubectl create secret generic x --from-literal=password=[REDACTED]`},
		{"uri userinfo", `psql postgres://user:pass@db.internal/vctl`, `psql postgres://user:[REDACTED]@db.internal/vctl`},
		// The "@" must survive whatever set of rules ran before the URI one —
		// it is what keeps the redacted URI a URI.
		{"uri userinfo beside other secrets", `run --token=abc postgres://user:pass@db.internal/vctl`, `run --token=[REDACTED] postgres://user:[REDACTED]@db.internal/vctl`},
		{"ordinary args", `kubectl get pods -n vctl`, `kubectl get pods -n vctl`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Arguments(tt.in); got != tt.want {
				t.Fatalf("Arguments() = %q, want %q", got, tt.want)
			}
		})
	}
}
