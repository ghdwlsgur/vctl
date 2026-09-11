// Package kubeconfig edits a kubeconfig file the way `vctl k8s use` needs to:
// add or replace the entries vctl owns — named vctl-<cluster> — and set the
// current context, while leaving every other cluster, user, context and any
// key this package does not know about exactly as it found them. It is a
// YAML edit, not a kubeconfig model: client-go would be a dependency the size
// of the rest of the binary for three list edits and one string.
package kubeconfig

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/ghdwlsgur/vctl/internal/securefile"
)

// NamedCluster, NamedUser and NamedContext are kubeconfig's list items. The
// inner maps are kept generic so fields this package never sets survive a
// round trip.
type NamedCluster struct {
	Name    string         `yaml:"name"`
	Cluster map[string]any `yaml:"cluster"`
}

type NamedUser struct {
	Name string         `yaml:"name"`
	User map[string]any `yaml:"user"`
}

type NamedContext struct {
	Name    string         `yaml:"name"`
	Context map[string]any `yaml:"context"`
}

// File is a kubeconfig. Extra catches top-level keys this package does not
// model, so they are written back untouched.
type File struct {
	APIVersion     string         `yaml:"apiVersion"`
	Kind           string         `yaml:"kind"`
	Preferences    map[string]any `yaml:"preferences,omitempty"`
	Clusters       []NamedCluster `yaml:"clusters"`
	Users          []NamedUser    `yaml:"users"`
	Contexts       []NamedContext `yaml:"contexts"`
	CurrentContext string         `yaml:"current-context,omitempty"`
	Extra          map[string]any `yaml:",inline"`
}

// DefaultPath is where kubectl would look: the first entry of KUBECONFIG, else
// ~/.kube/config. kubectl merges every KUBECONFIG entry for reads but writes
// current-context to the first, so that is the one worth editing.
func DefaultPath() (string, error) {
	if env := os.Getenv("KUBECONFIG"); env != "" {
		first, _, _ := strings.Cut(env, string(os.PathListSeparator))
		if first != "" {
			return first, nil
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".kube", "config"), nil
}

// Load reads a kubeconfig. A missing file is an empty one, so the first
// `vctl k8s use` on a new machine creates it.
func Load(path string) (*File, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &File{APIVersion: "v1", Kind: "Config"}, nil
	}
	if err != nil {
		return nil, err
	}
	var f File
	if err := yaml.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if f.APIVersion == "" {
		f.APIVersion = "v1"
	}
	if f.Kind == "" {
		f.Kind = "Config"
	}
	return &f, nil
}

// Save writes the file atomically, mode 0600, creating ~/.kube if needed. A
// kubeconfig may hold credentials for other clusters; it is never left
// world-readable, whatever mode it had.
func (f *File) Save(path string) error {
	out, err := yaml.Marshal(f)
	if err != nil {
		return err
	}
	if err := securefile.EnsurePrivateDir(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return securefile.WriteAtomic(path, out, 0o600)
}

// SetCluster adds or replaces the cluster entry called name.
func (f *File) SetCluster(name string, cluster map[string]any) {
	for i := range f.Clusters {
		if f.Clusters[i].Name == name {
			f.Clusters[i].Cluster = cluster
			return
		}
	}
	f.Clusters = append(f.Clusters, NamedCluster{Name: name, Cluster: cluster})
}

// SetUser adds or replaces the user entry called name.
func (f *File) SetUser(name string, user map[string]any) {
	for i := range f.Users {
		if f.Users[i].Name == name {
			f.Users[i].User = user
			return
		}
	}
	f.Users = append(f.Users, NamedUser{Name: name, User: user})
}

// SetContext adds or replaces the context entry called name.
func (f *File) SetContext(name string, ctx map[string]any) {
	for i := range f.Contexts {
		if f.Contexts[i].Name == name {
			f.Contexts[i].Context = ctx
			return
		}
	}
	f.Contexts = append(f.Contexts, NamedContext{Name: name, Context: ctx})
}

// Context returns the context called name, if any.
func (f *File) Context(name string) (map[string]any, bool) {
	for _, c := range f.Contexts {
		if c.Name == name {
			return c.Context, true
		}
	}
	return nil, false
}

// Cluster returns the cluster entry called name, if any.
func (f *File) Cluster(name string) (map[string]any, bool) {
	for _, c := range f.Clusters {
		if c.Name == name {
			return c.Cluster, true
		}
	}
	return nil, false
}

// Use sets the current context.
func (f *File) Use(context string) { f.CurrentContext = context }
