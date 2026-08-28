package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/ui"
	"github.com/ghdwlsgur/vctl/internal/vaultc"
)

func kvExecCmd(env CommandEnv) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "exec <word|path> -- <command> [args...]",
		Aliases: []string{"run"},
		Short:   "Run a command with a secret's fields filled in — never shown",
		Long: `exec runs a command with a secret's fields filled in, and makes sure they are
never shown: not by you, not by the command, not to whatever is reading the
output — an AI agent driving this terminal included.

  vctl kv exec gitlab-albert -- curl -H 'PRIVATE-TOKEN: {token}' https://gitlab.example/api/v4/user
  vctl kv exec vctl-postgres -- PGPASSWORD={password} psql -h db -U {username} vctl
  vctl kv exec ansible-vault -- ansible-vault view x.yml --vault-password-file {password:file}

{key} anywhere in the command becomes that field's value. A leading NAME={key}
word sets an environment variable instead, the way env(1) does, which keeps the
value out of the argument list. {key:file} writes the value to a file only you
can read and puts the file's path there; the file is gone when the command
exits. Braces that do not name a field are left alone, so jq and awk still work.

The command's output is filtered on the way out: every occurrence of a value
that was filled in — and its base64 and URL-encoded forms — is replaced with
[REDACTED:key], and you are told how many times that happened. The Vault token
is not passed on; the child gets the fields you named and nothing else from
Vault. The secret is resolved the way 'vctl kv' resolves one: a word that
matches exactly one secret, or a full path. Without a terminal an ambiguous word
is an error, never a guess.`,
		Args:              cobra.MinimumNArgs(2),
		ValidArgsFunction: firstArgOnly(completeKVPath(env)),
		RunE: func(cmd *cobra.Command, args []string) error {
			if cmd.ArgsLenAtDash() != 1 {
				return fmt.Errorf("name one secret, then -- and the command: vctl kv exec <secret> -- <command> [args...]")
			}
			return env.withKV(cmd.Context(), func(a *app.App, kv kvReader) error {
				ctx := cmd.Context()
				path, err := resolveKVPath(ctx, kv, kvRoot(a.Cfg), args[:1])
				if err != nil {
					return err
				}
				sec, err := kv.ReadKVSecret(ctx, path, 0)
				if err != nil {
					return kvError(err, path)
				}
				return runKVExec(ctx, sec, args[1:], os.Stdin, os.Stdout, os.Stderr)
			})
		},
	}
	return gate(cmd, "kv")
}

// runKVExec fills the command in from the secret and runs it behind a mask.
// Split from the command so tests can run a real child against a fake secret
// and read what came out.
func runKVExec(ctx context.Context, sec vaultc.KVSecret, words []string, stdin io.Reader, stdout, stderr io.Writer) error {
	f, err := fillKV(sec, words)
	if err != nil {
		return err
	}
	defer f.cleanup()
	if f.uses == 0 {
		return fmt.Errorf("nothing to fill in: the command names no field of %s in braces (fields: %s)",
			sec.Path, strings.Join(kvKeyNames(sec), ", "))
	}
	if len(f.argv) == 0 {
		return fmt.Errorf("no command after the NAME={key} assignments")
	}

	mask := newKVRedactor(f.values)
	out, errw := mask.writer(stdout), mask.writer(stderr)
	child := exec.CommandContext(ctx, f.argv[0], f.argv[1:]...)
	child.Stdin, child.Stdout, child.Stderr = stdin, out, errw
	child.Env = append(envWithoutVaultToken(), f.env...)
	runErr := runChild(child)
	_ = out.Flush()
	_ = errw.Flush()
	if n := mask.total(); n > 0 {
		ui.Warnf(stderr, "masked %d occurrence(s) of %s in the output — the command echoed a secret", n, mask.report())
	}
	return runErr
}

// envWithoutVaultToken is the inherited environment minus VAULT_TOKEN.
//
// The contract of kv exec is that the child gets the fields it was given and
// nothing else from Vault. A token in the operator's shell is every capability
// they hold, and a command that only needed one password should not inherit it
// by accident. `vctl exec` is the command that hands the token on, on purpose.
func envWithoutVaultToken() []string {
	env := os.Environ()
	out := make([]string, 0, len(env))
	for _, kv := range env {
		if strings.HasPrefix(kv, "VAULT_TOKEN=") {
			continue
		}
		out = append(out, kv)
	}
	return out
}

// runChild runs a prepared child, lets it own ^C, and turns its exit status
// into a CommandExitError so main exits with it.
//
// signal.Notify rather than signal.Ignore: Ignore sets SIG_IGN, which the child
// inherits across exec and keeps — a plain sh or psql would then ignore ^C too.
// Notify only detaches vctl's own handler, so the child terminates on ^C while
// vctl stays alive to flush the mask and report what it caught.
func runChild(child *exec.Cmd) error {
	sigint := make(chan os.Signal, 1)
	signal.Notify(sigint, os.Interrupt)
	defer signal.Stop(sigint)
	if err := child.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return &CommandExitError{Code: ee.ExitCode()}
		}
		return err
	}
	return nil
}

// kvField matches {key} and {key:file}: a field name in braces, spelled with
// the characters KV keys use. What it does not match is left as typed — an awk
// program, a JSON literal, a ${VAR} whose name is not a field.
var kvField = regexp.MustCompile(`\{([A-Za-z0-9_.-]+)(:file)?\}`)

// envName is what env(1) accepts on the left of an assignment.
var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// kvFill is a command with a secret filled in: the argv to run, the extra
// environment, the values that went somewhere (which is what the mask must
// catch), and the directory holding any {key:file} files.
type kvFill struct {
	argv   []string
	env    []string
	values map[string]string
	uses   int
	tmpDir string
}

// fillKV substitutes the secret into the words after --. Leading NAME=value
// words are environment assignments, as for env(1); the rest is the command.
func fillKV(sec vaultc.KVSecret, words []string) (*kvFill, error) {
	f := &kvFill{values: map[string]string{}}
	i := 0
	for ; i < len(words); i++ {
		name, val, ok := strings.Cut(words[i], "=")
		if !ok || !envName.MatchString(name) {
			break
		}
		filled, err := f.fill(sec, val)
		if err != nil {
			return f, err
		}
		f.env = append(f.env, name+"="+filled)
	}
	for _, w := range words[i:] {
		filled, err := f.fill(sec, w)
		if err != nil {
			return f, err
		}
		f.argv = append(f.argv, filled)
	}
	return f, nil
}

// fill replaces every {key} and {key:file} in s that names a field of sec.
func (f *kvFill) fill(sec vaultc.KVSecret, s string) (string, error) {
	var ferr error
	out := kvField.ReplaceAllStringFunc(s, func(m string) string {
		sub := kvField.FindStringSubmatch(m)
		key, asFile := sub[1], sub[2] != ""
		v, ok := sec.Data[key]
		if !ok {
			return m
		}
		f.uses++
		f.values[key] = v
		if !asFile {
			return v
		}
		p, err := f.fileFor(key, v)
		if err != nil {
			ferr = err
			return m
		}
		return p
	})
	return out, ferr
}

// fileFor writes one value to a file only this user can read, in a directory
// only this user can enter, and returns its path.
func (f *kvFill) fileFor(key, v string) (string, error) {
	if f.tmpDir == "" {
		d, err := os.MkdirTemp("", "vctl-kv-")
		if err != nil {
			return "", fmt.Errorf("temp dir for {%s:file}: %w", key, err)
		}
		f.tmpDir = d
	}
	p := filepath.Join(f.tmpDir, key)
	if err := os.WriteFile(p, []byte(v), 0o600); err != nil {
		return "", fmt.Errorf("write {%s:file}: %w", key, err)
	}
	return p, nil
}

// cleanup removes the {key:file} files. Nothing of the secret outlives the
// command.
func (f *kvFill) cleanup() {
	if f.tmpDir != "" {
		_ = os.RemoveAll(f.tmpDir)
	}
}

// kvRedactor redacts filled-in values from a stream. It knows the exact bytes, so
// the filter is exact: each value, plus the base64 and URL-encoded forms a
// command is likely to print it in. Values shorter than kvMaskMin are not
// masked — a three-character "secret" would redact every "abc" on the screen,
// and it was never a secret.
//
// A safety net, not a guarantee: a value printed in hex, or split across two
// lines, passes. The guarantee is the shape of the command — the value never
// needs to be printed — and the mask is for the times a command prints it
// anyway.
type kvRedactor struct {
	mu      sync.Mutex
	needles []kvNeedle
	hits    map[string]int
}

type kvNeedle struct {
	bytes []byte
	key   string
}

const kvMaskMin = 4

func newKVRedactor(values map[string]string) *kvRedactor {
	m := &kvRedactor{hits: map[string]int{}}
	for key, v := range values {
		if len(v) < kvMaskMin {
			continue
		}
		seen := map[string]bool{}
		for _, form := range []string{
			v,
			base64.StdEncoding.EncodeToString([]byte(v)),
			base64.RawStdEncoding.EncodeToString([]byte(v)),
			base64.URLEncoding.EncodeToString([]byte(v)),
			base64.RawURLEncoding.EncodeToString([]byte(v)),
			url.QueryEscape(v),
		} {
			if seen[form] {
				continue
			}
			seen[form] = true
			m.needles = append(m.needles, kvNeedle{[]byte(form), key})
		}
	}
	// Longest first, so a form that contains another is replaced whole.
	sort.SliceStable(m.needles, func(i, j int) bool { return len(m.needles[i].bytes) > len(m.needles[j].bytes) })
	return m
}

// redact replaces every complete needle in buf and counts what it replaced.
func (m *kvRedactor) redact(buf []byte) []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, n := range m.needles {
		if c := bytes.Count(buf, n.bytes); c > 0 {
			m.hits[n.key] += c
			buf = bytes.ReplaceAll(buf, n.bytes, []byte("[REDACTED:"+n.key+"]"))
		}
	}
	return buf
}

// holdback is how many trailing bytes of buf could be the start of a needle
// whose rest has not arrived yet. Those wait for the next write; everything
// before them is safe to pass on.
func (m *kvRedactor) holdback(buf []byte) int {
	hold := 0
	for _, n := range m.needles {
		for l := min(len(n.bytes)-1, len(buf)); l > hold; l-- {
			if bytes.HasSuffix(buf, n.bytes[:l]) {
				hold = l
				break
			}
		}
	}
	return hold
}

func (m *kvRedactor) total() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, c := range m.hits {
		n += c
	}
	return n
}

// report names what was masked, per field, in a stable order.
func (m *kvRedactor) report() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	keys := make([]string, 0, len(m.hits))
	for k := range m.hits {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = fmt.Sprintf("%s ×%d", k, m.hits[k])
	}
	return strings.Join(parts, ", ")
}

// maskWriter is one masked stream. stdout and stderr each get their own, over
// the same kvMask, so the count covers both.
type maskWriter struct {
	m    *kvRedactor
	w    io.Writer
	tail []byte
}

func (m *kvRedactor) writer(w io.Writer) *maskWriter { return &maskWriter{m: m, w: w} }

// Write holds back first and redacts second. The order matters: one needle
// can be a proper prefix of another — base64 without its padding is the
// padded form minus "=" — and redacting the moment the short one is complete
// would print the long one's tail. So a suffix that could still grow into a
// longer needle waits, whole, for the next write, and only what cannot is
// redacted and released.
func (mw *maskWriter) Write(p []byte) (int, error) {
	buf := make([]byte, 0, len(mw.tail)+len(p))
	buf = append(append(buf, mw.tail...), p...)
	hold := mw.m.holdback(buf)
	if _, err := mw.w.Write(mw.m.redact(buf[:len(buf)-hold])); err != nil {
		return 0, err
	}
	mw.tail = append(mw.tail[:0], buf[len(buf)-hold:]...)
	return len(p), nil
}

// Flush redacts and releases what was held back. Called once the child has
// exited: there is no more output for a partial match to complete into, so
// whatever the tail is, it is final.
func (mw *maskWriter) Flush() error {
	if len(mw.tail) == 0 {
		return nil
	}
	_, err := mw.w.Write(mw.m.redact(mw.tail))
	mw.tail = nil
	return err
}
