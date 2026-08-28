package cli

import (
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/ui"
	"github.com/ghdwlsgur/vctl/internal/vaultc"
)

// kvHidden stands in for every hidden value. Fixed width on purpose: a mask
// that tracked the value's length would say how long the credential is.
const kvHidden = "••••••••"

// kvGetOpts are the flags a read takes. Declared once and attached to both the
// bare command and `get`, so `vctl kv gitlab --field token` and `vctl kv get
// gitlab --field token` are the same command spelled two ways.
type kvGetOpts struct {
	field   string
	reveal  bool
	version int
}

func addKVGetFlags(cmd *cobra.Command, o *kvGetOpts) {
	f := cmd.Flags()
	f.StringVar(&o.field, "field", "", "print this one value and nothing else (for scripts)")
	f.BoolVar(&o.reveal, "reveal", false, "show the values instead of masking them")
	f.IntVar(&o.version, "version", 0, "read this version instead of the current one")
	cmd.MarkFlagsMutuallyExclusive("field", "reveal")
}

func kvGetCmd(env CommandEnv) *cobra.Command {
	var opts kvGetOpts
	cmd := &cobra.Command{
		Use:   "get [word|path]",
		Short: "Show a secret's keys, and its values when asked",
		Long: `get shows what a secret holds. Name it by full path, or by a word — the way
'vctl ssh' takes a host: a word that matches one secret reads it, a word that
matches several opens a picker, and no argument picks from everything you can
list. Without a terminal a word has to match exactly one.

By default the keys are listed and the values masked, which answers "is the
field there" without putting a credential on the screen. --reveal shows the
values; --field <key> prints one value and nothing else, for a script.

  vctl kv get kv/teams/sre/gitlab-albert
  vctl kv get gitlab-albert --reveal
  TOKEN=$(vctl kv get kv/teams/sre/gitlab-albert --field token)

With -o json the data object is present only under --reveal. Without it the
output carries the key names and no data at all — absent, rather than a
placeholder something might take for the value.`,
		Args:              cobra.MaximumNArgs(1),
		ValidArgsFunction: firstArgOnly(completeKVPath(env)),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runKVGet(cmd, env, args, opts)
		},
	}
	addKVGetFlags(cmd, &opts)
	return supportsStructuredOutput(gate(cmd, "kv"))
}

// runKVGet is the read behind both `vctl kv [word|path]` and `vctl kv get`.
func runKVGet(cmd *cobra.Command, env CommandEnv, args []string, o kvGetOpts) error {
	format, err := requestedOutput(cmd)
	if err != nil {
		return err
	}
	if o.field != "" && format != outputTable {
		return fmt.Errorf("--field prints one bare value; it does not combine with --output %s", format)
	}
	if o.version < 0 {
		return fmt.Errorf("--version must be a version number, 1 or higher")
	}
	return env.withKV(cmd.Context(), func(a *app.App, kv kvReader) error {
		ctx := cmd.Context()
		path, err := resolveKVPath(ctx, kv, kvRoot(a.Cfg), args)
		if err != nil {
			return err
		}
		sec, err := kv.ReadKVSecret(ctx, path, o.version)
		if err != nil {
			if errors.Is(err, vaultc.ErrKVNotFound) && o.version == 0 {
				// A folder reads as nothing at all. One list tells the
				// operator which of the two they typed.
				if keys, lerr := kv.ListKV(ctx, path); lerr == nil && len(keys) > 0 {
					return fmt.Errorf("%s is a folder, not a secret — 'vctl kv list %s' shows what is under it", path, path)
				}
			}
			return kvError(err, path)
		}
		if o.field != "" {
			v, ok := sec.Data[o.field]
			if !ok {
				has := append(kvKeyNames(sec), sec.NonString...)
				return fmt.Errorf("%s has no field %q (has: %s)", path, o.field, strings.Join(has, ", "))
			}
			fmt.Fprintln(os.Stdout, v)
			return nil
		}
		if format != outputTable {
			return writeStructured(format, newKVGetOutput(sec, o.reveal))
		}
		if !o.reveal && kvViewerWanted(sec) {
			return viewKVSecret(sec, os.Stdin, os.Stdout)
		}
		renderKVSecret(os.Stdout, sec, o.reveal)
		return nil
	})
}

// kvGetOutput is the structured shape of one secret. Data is present only when
// the caller asked to reveal — absent, not a placeholder, so nothing downstream
// can mistake a mask for the value.
type kvGetOutput struct {
	Path           string            `json:"path"`
	Version        int               `json:"version,omitempty"`
	CreatedAt      *time.Time        `json:"created_at,omitempty"`
	DeletedAt      *time.Time        `json:"deleted_at,omitempty"`
	Destroyed      bool              `json:"destroyed,omitempty"`
	Keys           []string          `json:"keys"`
	NonStringKeys  []string          `json:"non_string_keys,omitempty"`
	Data           map[string]string `json:"data,omitempty"`
	CustomMetadata map[string]string `json:"custom_metadata,omitempty"`
}

func newKVGetOutput(sec vaultc.KVSecret, reveal bool) kvGetOutput {
	out := kvGetOutput{
		Path:           sec.Path,
		Version:        sec.Version,
		CreatedAt:      optionalTime(sec.CreatedAt),
		DeletedAt:      optionalTime(sec.DeletedAt),
		Destroyed:      sec.Destroyed,
		Keys:           kvKeyNames(sec),
		NonStringKeys:  sec.NonString,
		CustomMetadata: sec.CustomMetadata,
	}
	if reveal {
		out.Data = sec.Data
	}
	return out
}

// optionalTime renders the zero time as absence rather than year 1.
func optionalTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// kvKeyNames is the sorted list of a secret's string fields — the answer to
// "what is in here" that needs no value shown. Never nil: in JSON an empty
// secret has an empty key list, not a null.
func kvKeyNames(sec vaultc.KVSecret) []string {
	keys := slices.AppendSeq(make([]string, 0, len(sec.Data)), maps.Keys(sec.Data))
	slices.Sort(keys)
	return keys
}

// renderKVSecret prints a secret the way `vctl status` prints its rows: a
// heading with which version this is, then key by key. Values are masked unless
// reveal is set, and a deleted or destroyed version says so instead of showing
// an empty list that would read as a secret with no fields.
func renderKVSecret(w io.Writer, sec vaultc.KVSecret, reveal bool) {
	fmt.Fprintln(w, kvHeading(sec))

	switch {
	case sec.Destroyed:
		fmt.Fprintln(w, ui.Fail("this version was destroyed — its data is gone"))
		return
	case !sec.DeletedAt.IsZero():
		fmt.Fprintln(w, ui.Warn("this version was deleted "+sec.DeletedAt.Local().Format(ui.TimeLayout)+" — its data is hidden until undeleted"))
		return
	}

	rows := make([]ui.KV, 0, len(sec.Data)+len(sec.NonString))
	for _, k := range kvKeyNames(sec) {
		v := ui.Muted(kvHidden)
		if reveal {
			v = ui.Value(sec.Data[k])
		}
		rows = append(rows, ui.KV{Key: k, Raw: v})
	}
	for _, k := range sec.NonString {
		rows = append(rows, ui.KV{Key: k, Raw: ui.Muted("(not a string — not rendered here)")})
	}
	if len(rows) == 0 {
		fmt.Fprintln(w, ui.Muted("(no fields)"))
		return
	}
	ui.KVs(w, rows)
	if len(sec.CustomMetadata) > 0 {
		fmt.Fprintln(w, ui.Muted("metadata: "+joinSortedKV(sec.CustomMetadata)))
	}
	if !reveal && len(sec.Data) > 0 {
		fmt.Fprintln(w, ui.Muted("values hidden · --reveal shows them · --field <key> prints one"))
	}
}

// kvHeading is the one line that names a secret and says which version this is
// and how old — shared by the print and the viewer so they open the same way.
func kvHeading(sec vaultc.KVSecret) string {
	var meta []string
	if sec.Version > 0 {
		meta = append(meta, fmt.Sprintf("v%d", sec.Version))
	}
	if !sec.CreatedAt.IsZero() {
		meta = append(meta, sec.CreatedAt.Local().Format("2006-01-02")+" "+ui.StripANSI(ui.Ago(sec.CreatedAt)))
	}
	return ui.GroupHeading(sec.Path, strings.Join(meta, " · "))
}

// joinSortedKV renders a small map as "k=v k=v" in key order, so two runs of
// the same command print the same line.
func joinSortedKV(m map[string]string) string {
	var parts []string
	for _, k := range slices.Sorted(maps.Keys(m)) {
		parts = append(parts, k+"="+m[k])
	}
	return strings.Join(parts, " ")
}
