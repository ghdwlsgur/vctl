// Package doctor answers "why is this deployment not settling" before
// somebody has to read a reconcile log to find out.
//
// A reconcile that fails says one thing: the control plane could not be
// asked. Which of five reasons that was — no credentials filed, a stored
// auth_url nobody can reach, TLS that will not verify, a token without the
// scope to list services, a listing that stops partway — is the part that
// takes the time, and it is the same five every time.
//
// The judgement lived in the CLI and was typed with the renderer's ui.State,
// which made the terminal's palette the domain's vocabulary and blocked a
// machine-readable export — an API or a web view would have had to make the
// same judgements again. Severity is this package's own word now, and it is a
// string so the wire shape needs no translation.
//
// # Read-only, on both sides
//
// Every OpenStack call here is a GET behind an auth POST. Nothing touches
// membership, the VM snapshot or the run history: a command somebody reaches
// for when a farm is already misbehaving must not be able to make it worse,
// and "diagnostic" is exactly the word people use for the tool they run
// without thinking about what it writes.
package doctor

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/ghdwlsgur/vctl/internal/openstackapi"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/strutil"
)

// Severity ranks one check's answer.
type Severity string

const (
	OK   Severity = "ok"
	Warn Severity = "warn"
	Fail Severity = "fail"
)

// Check is one question and what came back.
type Check struct {
	Name     string   `json:"name"`
	Severity Severity `json:"severity"`
	Detail   string   `json:"detail"`
}

// Failed counts the checks that failed outright.
func Failed(cs []Check) int {
	var n int
	for _, c := range cs {
		if c.Severity == Fail {
			n++
		}
	}
	return n
}

// Credentials reads a deployment's admin credentials. Satisfied by
// farmcreds.Store.
type Credentials interface {
	ForFarm(ctx context.Context, id string) (openstackapi.Credentials, error)
}

// Runs reads the reconcile history. Satisfied by *store.Store.
type Runs interface {
	ReconcileRuns(ctx context.Context) (map[string]store.ReconcileRun, error)
}

// Doctor holds what a diagnosis needs.
type Doctor struct {
	Creds Credentials
	Runs  Runs

	// Timeout bounds each control-plane call. Zero takes the default, which
	// is shorter than the reconciler's: somebody is waiting at a terminal for
	// an answer about why something is slow.
	Timeout time.Duration
}

const defaultTimeout = 30 * time.Second

func (d Doctor) timeout() time.Duration {
	if d.Timeout > 0 {
		return d.Timeout
	}
	return defaultTimeout
}

// Diagnose asks, in the order a failure cascades: nothing below a failed
// check can be answered, so each one says why the rest are missing rather
// than repeating the same error five times.
func (d Doctor) Diagnose(ctx context.Context, id string, insecure bool) []Check {
	var out []Check
	add := func(name string, sev Severity, format string, args ...any) {
		out = append(out, Check{Name: name, Severity: sev, Detail: strutil.OneLine(fmt.Sprintf(format, args...))})
	}

	creds, err := d.Creds.ForFarm(ctx, id)
	if err != nil {
		add("Credentials", Fail, "%v", err)
		add("Keystone", Warn, "not attempted — there is nothing to authenticate with")
		return append(out, d.lastReconcile(ctx, id))
	}
	missing := MissingCredFields(creds)
	if len(missing) > 0 {
		add("Credentials", Warn, "found, but %s not set", strings.Join(missing, " and "))
	} else {
		add("Credentials", OK, "%s at %s", creds.Username, creds.AuthURL)
	}

	client, authErr := openstackapi.New(ctx, creds, insecure, d.timeout())
	if authErr != nil {
		// A TLS failure and an unreachable endpoint read the same in the error,
		// and they call for completely different next steps. Tell them apart by
		// probing the certificate directly — never by re-authenticating with
		// verification off, which would put this deployment's admin password on
		// an unverified channel to whatever is actually answering (the very
		// thing a TLS failure warns about). The probe opens a TLS handshake and
		// sends nothing.
		if !insecure && certificateIsTheProblem(ctx, creds.AuthURL, d.timeout()) {
			add("Keystone", Fail,
				"the endpoint answers TLS but its certificate does not verify — the certificate is the problem, not the route (%v)", authErr)
			return append(out, d.lastReconcile(ctx, id))
		}
		add("Keystone", Fail, "%v", authErr)
		return append(out, d.lastReconcile(ctx, id))
	}
	verified := "verified TLS"
	if insecure {
		verified = "TLS verification skipped"
	}
	add("Keystone", OK, "authenticated, %s", verified)

	// os-services and os-hypervisors are separate permissions and separate
	// failures: without services no controller is listed, without hypervisors a
	// compute node whose nova-compute is down disappears.
	svcs, svcErr := client.Services(ctx)
	if svcErr != nil {
		add("Nova services", Fail, "%v — controllers would not be listed", svcErr)
	} else {
		add("Nova services", OK, "%d", len(svcs))
	}
	hyps, hypErr := client.Hypervisors(ctx)
	if hypErr != nil {
		add("Nova hypervisors", Fail, "%v — stopped compute nodes would not be listed", hypErr)
	} else {
		add("Nova hypervisors", OK, "%d", len(hyps))
	}

	vms, vmErr := client.Instances(ctx)
	switch {
	case vmErr != nil && len(vms) > 0:
		// The listing stopped partway. Storing that is safe now, but it is the
		// state where a farm's VM count silently stops being the whole picture.
		add("Instances", Warn, "%d listed, then stopped: %v", len(vms), vmErr)
	case vmErr != nil:
		add("Instances", Fail, "%v", vmErr)
	default:
		add("Instances", OK, "%d, listing complete", len(vms))
	}

	if _, err := client.ProjectNames(ctx); err != nil {
		// Not fatal: the reconciler stores uuids and leaves the name column
		// alone rather than blanking what an earlier run found.
		add("Project names", Warn, "%v — VMs would be listed by project uuid", err)
	} else {
		add("Project names", OK, "resolvable")
	}

	return append(out, d.lastReconcile(ctx, id))
}

// certificateIsTheProblem reports whether authURL's TLS endpoint is reachable
// and completes a handshake but presents a certificate the system roots reject.
// That is the one case worth calling out separately: the route is fine, the
// certificate is not.
//
// It never authenticates and sends no request body — only a TLS handshake, once
// with verification off (does the endpoint speak TLS at all?) and, if so, once
// with verification on (does the certificate verify?). A password never leaves
// the process, so a MITM on a genuinely bad certificate learns nothing.
func certificateIsTheProblem(ctx context.Context, authURL string, timeout time.Duration) bool {
	u, err := url.Parse(authURL)
	if err != nil || u.Host == "" {
		return false
	}
	addr := u.Host
	if u.Port() == "" {
		addr = net.JoinHostPort(u.Hostname(), "443")
	}

	dialer := &net.Dialer{Timeout: timeout}
	handshake := func(verify bool) error {
		d := tls.Dialer{
			NetDialer: dialer,
			Config: &tls.Config{
				ServerName:         u.Hostname(),
				InsecureSkipVerify: !verify, // #nosec G402 -- diagnostic reachability probe, sends nothing
			},
		}
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			return err
		}
		return conn.Close()
	}

	// Unreachable or not TLS at all: not a certificate problem, it is the route.
	if err := handshake(false); err != nil {
		return false
	}
	// Speaks TLS but will not verify: the certificate is the problem.
	return handshake(true) != nil
}

// MissingCredFields names the credential fields a reconcile cannot run
// without. A missing field is a different problem from a missing credential,
// and the fix is different too.
func MissingCredFields(c openstackapi.Credentials) []string {
	var out []string
	for _, f := range []struct{ name, v string }{
		{"auth_url", c.AuthURL}, {"username", c.Username},
		{"password", c.Password}, {"project_name", c.ProjectName},
	} {
		if f.v == "" {
			out = append(out, f.name)
		}
	}
	return out
}

// lastReconcile reads what the run history already knows, so the checks above
// can be compared against what actually happened.
func (d Doctor) lastReconcile(ctx context.Context, id string) Check {
	runs, err := d.Runs.ReconcileRuns(ctx)
	if err != nil {
		return Check{Name: "Last reconcile", Severity: Warn, Detail: err.Error()}
	}
	r, ok := runs[id]
	if !ok {
		return Check{Name: "Last reconcile", Severity: Warn, Detail: "never run"}
	}
	switch {
	case r.SucceededAt == nil:
		return Check{Name: "Last reconcile", Severity: Fail,
			Detail: "never succeeded — " + orNone(r.LastError)}
	case r.LastError != "":
		return Check{Name: "Last reconcile", Severity: Warn,
			Detail: fmt.Sprintf("succeeded %s ago, failing since: %s",
				strutil.CompactDuration(time.Since(*r.SucceededAt)), r.LastError)}
	default:
		return Check{Name: "Last reconcile", Severity: OK,
			Detail: strutil.CompactDuration(time.Since(*r.SucceededAt)) + " ago"}
	}
}

func orNone(s string) string {
	if s == "" {
		return "no reason recorded"
	}
	return s
}
