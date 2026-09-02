package cli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	deploynode "github.com/ghdwlsgur/vctl/deploy/node"
)

// The drop-in pins the inventory hostname and, with the banner on, appends
// exactly the writable path the strict sandbox needs.
func TestNodeAgentDropInShape(t *testing.T) {
	d := nodeAgentDropIn("sre-srv-0100", true)
	for _, want := range []string{
		"ExecStart=\n",
		"--hostname 'sre-srv-0100'",
		"--motd /etc/motd",
		"ReadWritePaths=/etc/motd",
	} {
		if !strings.Contains(d, want) {
			t.Errorf("drop-in missing %q:\n%s", want, d)
		}
	}
	plain := nodeAgentDropIn("sre-srv-0100", false)
	if strings.Contains(plain, "motd") || strings.Contains(plain, "ReadWritePaths") {
		t.Errorf("motd remnants in the bannerless drop-in:\n%s", plain)
	}
}

// Credentials land 0600 under a 0700 dir, the units are written through
// quoted heredocs so nothing in them is shell-expanded, and the script itself
// proves the agent came up — set -e turns a dead unit into a failed install.
func TestInstallScriptShape(t *testing.T) {
	s := installScript("rid", "sid", "acc", "sre-srv-0100", true, nil)
	for _, want := range []string{
		"umask 077",
		"chmod 0700 /etc/vctl",
		"printf '%s' 'sid' > /etc/vctl/secret-id",
		"chmod 0600 /etc/vctl/secret-id",
		"printf '%s' 'vctl-node' > /etc/vctl/approle",
		"<<'VCTL_UNIT_EOF'",
		"<<'VCTL_DROPIN_EOF'",
		"[ -f /etc/motd ] || install -m 0644 /dev/null /etc/motd",
		"systemctl enable --now vctl-node-agent",
		"systemctl is-active --quiet vctl-node-agent",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("install script missing %q", want)
		}
	}
	// The unit rides in from the deploy tree — one source, no second copy.
	if !strings.Contains(s, strings.TrimRight(deploynode.AgentUnit, "\n")) {
		t.Error("install script does not carry the embedded deploy unit verbatim")
	}
	if strings.Contains(s, "/etc/hosts") {
		t.Error("no pins requested but the script still touches /etc/hosts")
	}
}

// Control-plane pins ride as the exact marker block the ansible role's
// blockinfile manages, so a later fleet run takes ownership of the same block
// instead of stacking a second copy — and only when the marker is absent AND a
// pinned name does not resolve, so working internal DNS wins. Measured twice
// in one day: agents `active` while every report died on "no such host" for
// names only the workstation could resolve.
func TestInstallScriptPinsUseTheAnsibleMarkerBlock(t *testing.T) {
	s := installScript("rid", "sid", "acc", "h", false, []hostPin{
		{IP: "192.0.2.10", Name: "vault.sre.local"},
		{IP: "192.0.2.10", Name: "vctl-postgres.sre.local"},
	})
	for _, want := range []string{
		"grep -q '# BEGIN VCTL AUDIT (vault/postgres)' /etc/hosts",
		"! getent hosts 'vault.sre.local' >/dev/null 2>&1 || ! getent hosts 'vctl-postgres.sre.local' >/dev/null 2>&1",
		"# BEGIN VCTL AUDIT (vault/postgres)\n192.0.2.10 vault.sre.local\n192.0.2.10 vctl-postgres.sre.local\n# END VCTL AUDIT (vault/postgres)",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("install script missing pin block piece:\n%s", want)
		}
	}
}

// makeAgentArchive builds a tar.gz holding a vctl-agent member, the shape the
// release publishes.
func makeAgentArchive(t *testing.T, body []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "vctl-agent", Mode: 0o755, Size: int64(len(body))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// One download serves every later install: the verified archive lands in the
// cache and a second fetch never touches the release URL again — but a
// corrupted cache is re-verified against checksums.txt and replaced rather
// than pushed.
func TestReleaseSourceCachesTheVerifiedArchive(t *testing.T) {
	agent := []byte("#!agent-binary")
	archive := makeAgentArchive(t, agent)
	sum := sha256.Sum256(archive)

	var archiveHits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/checksums.txt":
			fmt.Fprintf(w, "%s  vctl-agent_9.9.9_linux_amd64.tar.gz\n", hex.EncodeToString(sum[:]))
		case "/vctl-agent_9.9.9_linux_amd64.tar.gz":
			archiveHits++
			_, _ = w.Write(archive)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	r := releaseSource{base: srv.URL, archive: "vctl-agent_9.9.9_linux_amd64.tar.gz", cacheDir: t.TempDir()}
	for i := 0; i < 2; i++ {
		got, err := r.agent(context.Background())
		if err != nil {
			t.Fatalf("fetch %d: %v", i, err)
		}
		if !bytes.Equal(got, agent) {
			t.Fatalf("fetch %d returned wrong binary", i)
		}
	}
	if archiveHits != 1 {
		t.Fatalf("archive downloaded %d times, want 1 (second fetch must ride the cache)", archiveHits)
	}

	// Corrupt the cache: the re-verification must catch it and re-download.
	if err := os.WriteFile(filepath.Join(r.cacheDir, r.archive), []byte("rotten"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := r.agent(context.Background()); err != nil {
		t.Fatalf("fetch after corruption: %v", err)
	}
	if archiveHits != 2 {
		t.Fatalf("archive downloaded %d times, want 2 (corrupted cache must not be served)", archiveHits)
	}
}

// A tampered archive — one whose bytes do not match the release's own
// checksums.txt — must never reach a host.
func TestReleaseSourceRejectsAChecksumMismatch(t *testing.T) {
	archive := makeAgentArchive(t, []byte("evil"))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/checksums.txt":
			fmt.Fprintln(w, strings.Repeat("0", 64)+"  a.tar.gz")
		case "/a.tar.gz":
			_, _ = w.Write(archive)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	r := releaseSource{base: srv.URL, archive: "a.tar.gz", cacheDir: t.TempDir()}
	if _, err := r.agent(context.Background()); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("err = %v, want checksum rejection", err)
	}
}

// The archive must actually contain the agent; anything else is a packaging
// failure worth naming.
func TestExtractAgentReportsAMissingMember(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	_ = tw.WriteHeader(&tar.Header{Name: "README.md", Mode: 0o644, Size: 2})
	_, _ = tw.Write([]byte("hi"))
	_ = tw.Close()
	_ = gz.Close()
	if _, err := extractAgent(buf.Bytes()); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("err = %v, want not-found", err)
	}
}

func TestURLHostname(t *testing.T) {
	for in, want := range map[string]string{
		"https://vault.sre.local":      "vault.sre.local",
		"https://vault.sre.local:8200": "vault.sre.local",
		"not a url":                    "",
		"":                             "",
	} {
		if got := urlHostname(in); got != want {
			t.Errorf("urlHostname(%q) = %q, want %q", in, got, want)
		}
	}
}
