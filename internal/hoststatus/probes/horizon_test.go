package probes

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func writeHorizonConf(t *testing.T, root, body string) {
	t.Helper()
	dir := filepath.Join(root, "etc", "kolla", "haproxy", "services.d")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "horizon.cfg"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// A farm binds Horizon several times and nothing in the config says which one a
// person can open. All of them are reported, best first: which one somebody
// needs depends on where they are sitting, and leading with an internal VIP is
// worse than leading with nothing — it looks like an answer and fails in a
// browser.
func TestHorizonPrefersAnAddressSomebodyCanOpen(t *testing.T) {
	for _, tc := range []struct {
		name, conf string
		want       []string
	}{
		{
			// Measured shape: internal TLS, internal plain, external TLS.
			name: "external TLS beats internal TLS",
			conf: `frontend horizon_front
    bind 172.16.0.10:443 ssl crt /etc/haproxy/certificates/haproxy-internal.pem alpn h2,http/1.1
    bind 172.16.0.10:80
    bind 192.168.10.10:443 ssl crt /etc/haproxy/certificates/haproxy.pem
    server aio01 172.16.0.11:80 check`,
			want: []string{"https://192.168.10.10", "https://172.16.0.10", "http://172.16.0.10"},
		},
		{
			name: "TLS breaks the tie on the same network",
			conf: `    bind 192.168.201.150:80
    bind 192.168.201.150:443 ssl crt /etc/haproxy/certificates/haproxy.pem`,
			want: []string{"https://192.168.201.150", "http://192.168.201.150"},
		},
		{
			name: "one internal bind is still an answer",
			conf: `    bind 192.168.201.130:80`,
			want: []string{"http://192.168.201.130"},
		},
		{
			// A backend is a single controller. Sending somebody there bypasses
			// the VIP and breaks the moment that host is the one being patched.
			name: "server lines are not addresses to hand out",
			conf: `    server sre-srv-0047 192.168.201.221:80 check inter 2000`,
			want: nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeHorizonConf(t, root, tc.conf)
			p := &OpenStack{root: root, operatorNets: []string{"192.168."}}
			got := p.horizonURLs()
			if !slices.Equal(got, tc.want) {
				t.Errorf("horizonURLs = %q, want %q", got, tc.want)
			}
		})
	}
}

// With no operator networks configured nothing is known to be reachable, so the
// ranking falls back to TLS alone rather than inventing a preference.
func TestHorizonWithoutOperatorNetworksStillAnswers(t *testing.T) {
	root := t.TempDir()
	writeHorizonConf(t, root, "    bind 10.0.0.1:80\n    bind 10.0.0.1:443 ssl crt /x.pem\n")
	p := &OpenStack{root: root}
	got := p.horizonURLs()
	if len(got) == 0 || got[0] != "https://10.0.0.1" {
		t.Errorf("horizonURLs = %q, want the TLS bind first", got)
	}
}

// A farm with no dashboard says nothing. "http://" or a bare colon would read
// as an address that does not work.
func TestHorizonIsEmptyWhenThereIsNoDashboard(t *testing.T) {
	if got := (&OpenStack{root: t.TempDir()}).horizonURLs(); len(got) != 0 {
		t.Errorf("horizonURLs = %q, want empty", got)
	}
}
