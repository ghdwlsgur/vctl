package agent

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ghdwlsgur/vctl/internal/securefile"
)

func TestWriteFileAtomicWrites0600(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token-sink")
	if err := securefile.WriteAtomic(path, []byte("token"), 0o600); err != nil {
		t.Fatal(err)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "token" {
		t.Fatalf("content = %q", string(b))
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("perm = %o, want 600", got)
	}
}

func TestWriteFileAtomicRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "token-sink")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	if err := securefile.WriteAtomic(link, []byte("token"), 0o600); err == nil {
		t.Fatal("writeFileAtomic accepted a symlink sink")
	}

	b, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "old" {
		t.Fatalf("target content = %q", string(b))
	}
}

func TestWriteFileAtomicRejectsDirectory(t *testing.T) {
	if err := securefile.WriteAtomic(t.TempDir(), []byte("token"), 0o600); err == nil {
		t.Fatal("writeFileAtomic accepted a directory sink")
	}
}
