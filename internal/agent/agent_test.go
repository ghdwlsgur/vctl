package agent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFileAtomicWrites0600(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token-sink")
	if err := writeFileAtomic(path, []byte("token"), 0o600); err != nil {
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
