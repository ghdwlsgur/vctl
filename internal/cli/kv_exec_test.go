package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/ghdwlsgur/vctl/internal/authz"
	"github.com/ghdwlsgur/vctl/internal/vaultc"
)

// execSecret has a value long enough to mask, a username, and a value too
// short to be a secret.
func execSecret() vaultc.KVSecret {
	return vaultc.KVSecret{
		Path: "kv/teams/sre/example",
		Data: map[string]string{"token": "tok-abcdef-123456", "username": "someone", "pin": "9"},
	}
}

func TestFillKVSubstitutesFieldsAndLeavesOtherBracesAlone(t *testing.T) {
	f, err := fillKV(execSecret(), []string{
		"curl", "-H", "PRIVATE-TOKEN: {token}", "-u", "{username}:{token}", "{nope}", "awk", "{print $1}",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer f.cleanup()
	want := []string{"curl", "-H", "PRIVATE-TOKEN: tok-abcdef-123456", "-u", "someone:tok-abcdef-123456", "{nope}", "awk", "{print $1}"}
	if fmt.Sprint(f.argv) != fmt.Sprint(want) {
		t.Errorf("argv = %q\nwant   %q", f.argv, want)
	}
	if len(f.env) != 0 {
		t.Errorf("env = %v; want no environment assignments", f.env)
	}
	if f.values["token"] == "" || f.values["username"] == "" || f.values["pin"] != "" {
		t.Errorf("values = %v; want exactly the fields that were used", f.values)
	}
}

// Leading NAME=value words are the environment, as for env(1); the first word
// that is not one starts the command — even if it contains "=".
func TestFillKVTakesLeadingAssignmentsAsEnvironment(t *testing.T) {
	f, err := fillKV(execSecret(), []string{"PGPASSWORD={token}", "PGUSER={username}", "psql", "-h", "db", "--set=x={token}"})
	if err != nil {
		t.Fatal(err)
	}
	defer f.cleanup()
	if fmt.Sprint(f.env) != fmt.Sprint([]string{"PGPASSWORD=tok-abcdef-123456", "PGUSER=someone"}) {
		t.Errorf("env = %q", f.env)
	}
	if fmt.Sprint(f.argv) != fmt.Sprint([]string{"psql", "-h", "db", "--set=x=tok-abcdef-123456"}) {
		t.Errorf("argv = %q", f.argv)
	}

	f2, err := fillKV(execSecret(), []string{"--opt={token}", "cmd"})
	if err != nil {
		t.Fatal(err)
	}
	if len(f2.env) != 0 || f2.argv[0] != "--opt=tok-abcdef-123456" {
		t.Errorf("a flag with = was taken for an assignment: env=%v argv=%v", f2.env, f2.argv)
	}
}

func TestFillKVWritesFileFormsOnlyYouCanRead(t *testing.T) {
	f, err := fillKV(execSecret(), []string{"tool", "--password-file", "{token:file}"})
	if err != nil {
		t.Fatal(err)
	}
	p := f.argv[2]
	got, err := os.ReadFile(p)
	if err != nil || string(got) != "tok-abcdef-123456" {
		t.Fatalf("file %s = %q, %v", p, got, err)
	}
	if runtime.GOOS != "windows" {
		st, _ := os.Stat(p)
		if st.Mode().Perm() != 0o600 {
			t.Errorf("file mode = %o, want 0600", st.Mode().Perm())
		}
		dst, _ := os.Stat(f.tmpDir)
		if dst.Mode().Perm() != 0o700 {
			t.Errorf("dir mode = %o, want 0700", dst.Mode().Perm())
		}
	}
	// The value still counts for the mask: a command that cats the file has
	// printed the secret.
	if f.values["token"] == "" {
		t.Error("a {key:file} field was not recorded for masking")
	}
	f.cleanup()
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Errorf("file survived cleanup: %v", err)
	}
}

// A command that mentions no field would run with nothing filled in — most
// likely a typo in a brace — so it is refused with the field names to hand.
func TestRunKVExecRefusesACommandThatUsesNoField(t *testing.T) {
	var out, errb bytes.Buffer
	err := runKVExec(context.Background(), execSecret(), []string{"echo", "{Token}"}, nil, &out, &errb)
	if err == nil || !strings.Contains(err.Error(), "nothing to fill in") || !strings.Contains(err.Error(), "token") {
		t.Fatalf("err = %v", err)
	}
}

func TestKVMaskRedactsEveryFormAcrossChunkBoundaries(t *testing.T) {
	const tok, pw = "tok-abcdef-123456", "p@ss w0rd/x+y"
	m := newKVRedactor(map[string]string{"token": tok, "password": pw})
	var out bytes.Buffer
	w := m.writer(&out)
	text := "plain " + tok +
		" b64 " + base64.StdEncoding.EncodeToString([]byte(tok)) +
		" raw " + base64.RawURLEncoding.EncodeToString([]byte(pw)) +
		" url " + url.QueryEscape(pw) +
		" end\n"
	// One byte at a time: every needle straddles a write boundary.
	for i := 0; i < len(text); i++ {
		if _, err := w.Write([]byte{text[i]}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	want := "plain [REDACTED:token] b64 [REDACTED:token] raw [REDACTED:password] url [REDACTED:password] end\n"
	if out.String() != want {
		t.Errorf("masked = %q\nwant     %q", out.String(), want)
	}
	if m.total() != 4 || m.report() != "password ×2, token ×2" {
		t.Errorf("total = %d, report = %q", m.total(), m.report())
	}
}

// `echo "$X" | base64` encodes the value plus echo's newline. For a value
// whose length is not a multiple of three that changes the last base64 group,
// so the bare value's base64 never appears — and the newline form has to be a
// needle of its own or the commonest accident leaks whole. 17 bytes here.
func TestKVMaskCatchesTheBase64OfAnEchoedValue(t *testing.T) {
	const tok = "tok-abcdef-123456"
	echoed := base64.StdEncoding.EncodeToString([]byte(tok + "\n"))
	if strings.HasPrefix(echoed, base64.StdEncoding.EncodeToString([]byte(tok))) {
		t.Fatal("test value must not be a multiple of three bytes, or the bare form would match anyway")
	}
	m := newKVRedactor(map[string]string{"token": tok})
	var out bytes.Buffer
	w := m.writer(&out)
	if _, err := w.Write([]byte(echoed + "\n")); err != nil {
		t.Fatal(err)
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	if out.String() != "[REDACTED:token]\n" {
		t.Errorf("echoed base64 came through as %q", out.String())
	}
}

// Text that only looks like the start of a secret is released once it turns
// out not to be one, and a value too short to be a secret is never masked.
func TestKVMaskLeavesUnrelatedTextAndShortValuesAlone(t *testing.T) {
	m := newKVRedactor(map[string]string{"pin": "9", "token": "tok-abcdef-123456"})
	var out bytes.Buffer
	w := m.writer(&out)
	const text = "9 lives; tok-abcdef-12 is not the whole thing; tok- either\n"
	if _, err := w.Write([]byte(text)); err != nil {
		t.Fatal(err)
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	if out.String() != text {
		t.Errorf("unrelated text changed:\n%q\n%q", out.String(), text)
	}
	if m.total() != 0 {
		t.Errorf("total = %d, want 0", m.total())
	}
}

// The contract, end to end: a child that prints the value — from its
// environment, from its arguments, to stderr — shows nothing, and the operator
// is told how often it tried.
func TestRunKVExecMasksWhatTheChildEchoes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs /bin/sh")
	}
	var out, errb bytes.Buffer
	err := runKVExec(context.Background(), execSecret(),
		[]string{"X={token}", "sh", "-c", `printf '%s\n' "$X" '{token}'; printf '%s\n' "$X" >&2`},
		nil, &out, &errb)
	if err != nil {
		t.Fatal(err)
	}
	if out.String() != "[REDACTED:token]\n[REDACTED:token]\n" {
		t.Errorf("stdout = %q", out.String())
	}
	if strings.Contains(errb.String(), "tok-abcdef") {
		t.Errorf("stderr leaked the value: %q", errb.String())
	}
	for _, want := range []string{"[REDACTED:token]\n", "masked 3 occurrence(s) of token ×3"} {
		if !strings.Contains(errb.String(), want) {
			t.Errorf("stderr = %q, want %q in it", errb.String(), want)
		}
	}
}

func TestRunKVExecPassesTheExitStatusThrough(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs /bin/sh")
	}
	var out, errb bytes.Buffer
	err := runKVExec(context.Background(), execSecret(), []string{"sh", "-c", "echo {username}; exit 3"}, nil, &out, &errb)
	if code, ok := ChildExitCode(err); !ok || code != 3 {
		t.Fatalf("exit = %v (code %d, ok %v), want 3", err, code, ok)
	}
}

// The child gets the fields, not the token. A VAULT_TOKEN in the operator's
// shell would otherwise ride along into every command that needed one password.
func TestRunKVExecDoesNotHandTheChildAVaultToken(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs /bin/sh")
	}
	t.Setenv("VAULT_TOKEN", "must-not-reach-the-child")
	var out, errb bytes.Buffer
	err := runKVExec(context.Background(), execSecret(), []string{"sh", "-c", `echo "${VAULT_TOKEN:-unset}" {username}`}, nil, &out, &errb)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out.String(), "unset ") {
		t.Errorf("child saw VAULT_TOKEN: %q", out.String())
	}
}

// Wiring: gated as a read of kv like its siblings, with flag parsing off so the
// child's flags are never mistaken for ours.
func TestKVExecIsGatedAsReadWithFlagParsingOff(t *testing.T) {
	root := NewRoot(fakeDeps(t))
	ex := findCmd(findCmd(root, "kv"), "exec")
	if ex == nil {
		t.Fatal("kv exec missing")
	}
	if ex.Annotations["rbac.command"] != "kv" || ex.Annotations["rbac.class"] != string(authz.ClassRead) {
		t.Errorf("annotations = %v, want a read gate named kv", ex.Annotations)
	}
	if !ex.DisableFlagParsing {
		t.Error("flag parsing is on; the child's -x would be taken for one of ours")
	}
}

// The secret comes first and the command is the rest. A -- between them is
// tolerated for habit's sake and never required.
func TestSplitKVExecArgsTakesTheSecretThenTheCommand(t *testing.T) {
	for _, tc := range []struct {
		args   []string
		secret string
		words  []string
	}{
		{[]string{"gl", "curl", "-H", "x", "https://u"}, "gl", []string{"curl", "-H", "x", "https://u"}},
		{[]string{"gl", "--", "curl", "-H", "x"}, "gl", []string{"curl", "-H", "x"}},
		{[]string{"gl", "PGPASSWORD={password}", "psql"}, "gl", []string{"PGPASSWORD={password}", "psql"}},
	} {
		secret, words, err := splitKVExecArgs(tc.args)
		if err != nil || secret != tc.secret || fmt.Sprint(words) != fmt.Sprint(tc.words) {
			t.Errorf("split(%q) = %q %q %v", tc.args, secret, words, err)
		}
	}
	for _, args := range [][]string{
		{"gl"},             // no command
		{"gl", "--"},       // no command after the dash
		{"-x", "gl", "ls"}, // a flag where the secret goes
	} {
		if _, _, err := splitKVExecArgs(args); err == nil {
			t.Errorf("%q was accepted", args)
		}
	}
}
