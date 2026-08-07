package app

import (
	"context"
	"net"
	"testing"

	"github.com/ghdwlsgur/vctl/internal/config"
	"github.com/ghdwlsgur/vctl/internal/vaultc"
)

func testApp(t *testing.T, cfg *config.Config) *App {
	t.Helper()
	cfg.StateDir = t.TempDir()
	v, err := vaultc.New("http://127.0.0.1:1", nil, cfg.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	return &App{Cfg: cfg, Vault: v}
}

func TestDBEndpoint(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  *config.Config
		want string
	}{
		{"configured host", &config.Config{DBHost: "db.example.internal", DBPort: 5432}, "db.example.internal:5432"},
		{"local dsn", &config.Config{LocalDBDSN: "postgres://u:p@127.0.0.1:55433/vctl?sslmode=disable"}, "127.0.0.1:55433"},
		{"local dsn wins over host", &config.Config{DBHost: "db.example.internal", DBPort: 5432, LocalDBDSN: "postgres://u:p@127.0.0.1:5555/vctl"}, "127.0.0.1:5555"},
		{"no host configured", &config.Config{}, ""},
		{"unparseable dsn", &config.Config{LocalDBDSN: "::not a dsn::"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := testApp(t, tc.cfg).dbEndpoint(); got != tc.want {
				t.Errorf("dbEndpoint = %q, want %q", got, tc.want)
			}
		})
	}
}

// An endpoint that cannot be determined must read as reachable, so the normal
// connection attempt runs and reports its own error instead of the command
// being quietly answered from a snapshot.
func TestDatabaseAcceptsTreatsUnknownEndpointAsReachable(t *testing.T) {
	a := testApp(t, &config.Config{})
	if !a.databaseAccepts(context.Background()) {
		t.Error("an undeterminable endpoint was treated as unreachable")
	}
}

func TestDatabaseAcceptsDetectsListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	host, port, _ := net.SplitHostPort(addr)

	a := testApp(t, &config.Config{DBHost: host})
	a.Cfg.DBPort = atoi(t, port)
	if !a.databaseAccepts(context.Background()) {
		t.Fatalf("a live listener at %s was reported unreachable", addr)
	}

	ln.Close()
	if a.databaseAccepts(context.Background()) {
		t.Fatalf("a closed listener at %s was reported reachable", addr)
	}
}

// The probe exists only to spare the operator a login that cannot help. Any
// path that authenticates silently must not pay for it, and the local-DSN path
// does not authenticate at all.
func TestWouldPromptForLoginOnlyWhenAPromptIsPossible(t *testing.T) {
	t.Run("no credentials at all", func(t *testing.T) {
		if !testApp(t, &config.Config{}).WouldPromptForLogin() {
			t.Error("expected a prompt with no token and no AppRole credentials")
		}
	})
	t.Run("approle configured", func(t *testing.T) {
		a := testApp(t, &config.Config{AppRoleID: "role", AppRoleSecretID: "secret"})
		if a.WouldPromptForLogin() {
			t.Error("AppRole credentials authenticate silently; no prompt is possible")
		}
	})
	t.Run("local dsn bypasses vault", func(t *testing.T) {
		a := testApp(t, &config.Config{LocalDBDSN: "postgres://u:p@127.0.0.1:5432/vctl"})
		if a.WouldPromptForLogin() {
			t.Error("the local-DSN path never consults Vault; no prompt is possible")
		}
	})
}

// With no usable snapshot there is nothing to serve, so the probe must not run
// and the caller must fall through to the real connection attempt.
func TestSnapshotToServeInsteadNeedsAUsableSnapshot(t *testing.T) {
	a := testApp(t, &config.Config{DBHost: "127.0.0.1", DBPort: 1})
	if snap := a.snapshotToServeInstead(context.Background()); snap != nil {
		t.Error("a snapshot was served with nothing cached")
	}
}

func atoi(t *testing.T, s string) int {
	t.Helper()
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			t.Fatalf("bad port %q", s)
		}
		n = n*10 + int(r-'0')
	}
	return n
}
