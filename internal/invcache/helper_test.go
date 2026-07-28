package invcache

import (
	"encoding/json"
	"os"
	"testing"
)

// writeRaw writes a snapshot verbatim, bypassing Save's version stamping, so a
// test can produce a file this binary should refuse.
func writeRaw(t *testing.T, path string, snap *Snapshot) error {
	t.Helper()
	b, err := json.Marshal(snap)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}
