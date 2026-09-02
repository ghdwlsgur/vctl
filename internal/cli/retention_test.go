package cli

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/authz"
	"github.com/ghdwlsgur/vctl/internal/cli/internal/cmdkit"
	"github.com/ghdwlsgur/vctl/internal/config"
	"github.com/ghdwlsgur/vctl/internal/store"
)

// captureStderr runs fn with os.Stderr redirected, returning what was written.
// printAuditFootprint sends the warning there and the table to stdout, so the two
// have to be read separately.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stderr
	os.Stderr = w
	fn()
	os.Stderr = orig
	_ = w.Close()

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

// The exact shape that went unnoticed on 2026-07-29: kernel_event held 5,157 MB
// while the table was empty, and nothing anywhere said so. That is now a warning,
// and it names the command that reclaims it plus the cost of running it.
func TestFootprintWarnsOnParkedHighWaterMark(t *testing.T) {
	out := captureStderr(t, func() {
		if err := printAuditFootprint([]store.TableFootprint{
			{Table: "kernel_event", Bytes: 5157 * 1024 * 1024, Rows: 0, Dead: 0},
		}); err != nil {
			t.Fatal(err)
		}
	})

	for _, want := range []string{"kernel_event", "high-water mark", "VACUUM (FULL, ANALYZE) kernel_event", "exclusive lock"} {
		if !strings.Contains(out, want) {
			t.Errorf("warning missing %q\ngot: %s", want, out)
		}
	}
}

// A big table that is big because it holds data is not bloat. Warning on it would
// train people to ignore the warning.
func TestFootprintStaysQuietWhenTheRowsJustifyTheSize(t *testing.T) {
	out := captureStderr(t, func() {
		if err := printAuditFootprint([]store.TableFootprint{
			{Table: "kernel_event", Bytes: 5157 * 1024 * 1024, Rows: 4_748_267, Dead: 0},
		}); err != nil {
			t.Fatal(err)
		}
	})
	if strings.Contains(out, "high-water mark") {
		t.Errorf("warned about a table whose rows justify its size:\n%s", out)
	}
}

// A small table must not warn either, whatever its row count.
func TestFootprintStaysQuietWhenSmall(t *testing.T) {
	out := captureStderr(t, func() {
		if err := printAuditFootprint([]store.TableFootprint{
			{Table: "kernel_event", Bytes: 48 * 1024, Rows: 0, Dead: 0},
			{Table: "audit_session", Bytes: 160 * 1024, Rows: 246, Dead: 0},
		}); err != nil {
			t.Fatal(err)
		}
	})
	if strings.Contains(out, "high-water mark") {
		t.Errorf("warned about a small table:\n%s", out)
	}
}

// retention reports; it must never be able to delete. Class is what the gate
// reads, so pinning it here is what stops the command from quietly becoming a
// mutate again — and "prune" must be gone, not merely unused.
func TestRetentionIsGatedAsRead(t *testing.T) {
	class, ok := authz.ClassOf("retention")
	if !ok {
		t.Fatal("retention is not in the gated catalog")
	}
	if class != authz.ClassRead {
		t.Fatalf("retention class = %v, want ClassRead", class)
	}
	if _, ok := authz.ClassOf("prune"); ok {
		t.Fatal("prune is still in the gated catalog")
	}
}

// Retention deletion is an automation interface, not an operator command. The
// CronJob must be able to invoke it, while ordinary help and app RBAC do not
// advertise a destructive path that human credentials cannot authorize.
func TestPruneIsAHiddenAutomationCommand(t *testing.T) {
	cmd := findCmd(NewRoot(Dependencies{}), "prune")
	if cmd == nil {
		t.Fatal("the retention CronJob has no prune command to invoke")
	}
	if !cmd.Hidden {
		t.Fatal("prune is visible in operator help")
	}
	if _, ok := authz.ClassOf("prune"); ok {
		t.Fatal("the AppRole-only prune command was added to human app RBAC")
	}
}

func TestOpenStackPruneIsAHiddenAutomationCommand(t *testing.T) {
	cmd := findCmd(NewRoot(Dependencies{}), "openstack-prune-missing")
	if cmd == nil {
		t.Fatal("the OpenStack retention CronJob has no prune command to invoke")
	}
	if !cmd.Hidden {
		t.Fatal("openstack-prune-missing is visible in operator help")
	}
	if _, ok := authz.ClassOf("openstack-prune-missing"); ok {
		t.Fatal("the database-role-only OpenStack prune command was added to human app RBAC")
	}
}

func TestPruneRejectsAccessRetentionWhenSessionsAreKeptForever(t *testing.T) {
	cmd := pruneCmd(cmdkit.Env{NewApp: func() (*app.App, error) {
		return &app.App{Cfg: &config.Config{
			KernelRetentionDays: 14,
			AccessRetentionDays: 1095,
		}}, nil
	}})
	cmd.SetArgs(nil)
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "sessions are retained forever") {
		t.Fatalf("prune error = %v, want permanent-session attribution guard", err)
	}
}

func TestPruneCronJobUsesTheAutomationCommandAndCurrentRetentionContract(t *testing.T) {
	b, err := os.ReadFile("../../deploy/audit/prune-cronjob.yaml")
	if err != nil {
		t.Fatal(err)
	}
	manifest := string(b)
	for _, want := range []string{
		`args: ["prune", "--batch-size=5000"]`,
		"VCTL_KERNEL_RETENTION_DAYS",
		"VCTL_SESSION_RETENTION_DAYS",
		"VCTL_ACCESS_RETENTION_DAYS",
		"VCTL_AUTH_METHOD",
		"VCTL_KUBERNETES_ROLE",
	} {
		if !strings.Contains(manifest, want) {
			t.Errorf("prune CronJob is missing %q", want)
		}
	}
	if strings.Contains(manifest, "v0.1.14") {
		t.Error("prune CronJob still pins the obsolete image")
	}
	if strings.Contains(manifest, "vctl-prune-approle") || strings.Contains(manifest, "pods/exec") {
		t.Error("prune CronJob retains the old static-secret or pod-exec privilege path")
	}

	policy, err := os.ReadFile("../../deploy/vault/vctl-pruner.hcl")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(policy), `path "database/creds/vctl-pruner"`) {
		t.Error("pruner AppRole cannot obtain its delete-only database credential")
	}
	groups, err := os.ReadFile("../../deploy/vault/postgres-groups.sh")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(groups), "GRANT SELECT,DELETE ON access_log, audit_session, kernel_event TO vctl_pruner") {
		t.Error("pruner database role does not cover the full retention contract")
	}
}
