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
		{"kubernetes literal", `kubectl create secret generic x --from-literal=password=abc`, `kubectl create secret generic x --from-literal=password=[REDACTED]`},
		{"uri userinfo", `psql postgres://user:pass@db.internal/vctl`, `psql postgres://user:[REDACTED]@db.internal/vctl`},
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
