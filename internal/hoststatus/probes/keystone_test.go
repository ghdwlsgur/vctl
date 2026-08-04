package probes

import (
	"os"
	"path/filepath"
	"testing"
)

// nova.conf is present on controllers and compute nodes alike, which is what
// makes it the right source: a controller and its compute nodes name the same
// Keystone and are in fact one deployment.
func TestKeystoneURLIsReadFromNovaConf(t *testing.T) {
	root := t.TempDir()
	writeConf(t, root+"/etc/kolla/nova-compute/nova.conf", `
[DEFAULT]
transport_url = rabbit://openstack:hunter2@172.16.0.245:5672

[keystone_authtoken]
www_authenticate_uri = https://172.16.0.245:5000
auth_url = https://172.16.0.245:5000
username = nova
password = super-secret-value
`)
	p := &OpenStack{root: root}

	if got := p.keystoneURL(); got != "172.16.0.245:5000" {
		t.Errorf("keystoneURL() = %q, want the endpoint host", got)
	}
}

// The file holds service passwords. Only auth_url is parsed; nothing else in
// the file is looked at, and a value that is not an http(s) URL is refused —
// that is what stops a stray line becoming a deployment id in the inventory.
func TestKeystoneURLRefusesAnythingThatIsNotAnEndpoint(t *testing.T) {
	for name, conf := range map[string]string{
		"not a url":     "auth_url = super-secret-value\n",
		"no scheme":     "auth_url = 172.16.0.245:5000\n",
		"wrong scheme":  "auth_url = rabbit://172.16.0.245:5672\n",
		"empty":         "auth_url =\n",
		"no auth_url":   "password = hunter2\nusername = nova\n",
		"password only": "[keystone_authtoken]\npassword = auth_url-looking-value\n",
	} {
		root := t.TempDir()
		writeConf(t, root+"/etc/nova/nova.conf", conf)
		if got := (&OpenStack{root: root}).keystoneURL(); got != "" {
			t.Errorf("%s: keystoneURL() = %q, want empty", name, got)
		}
	}
}

// Two hosts of one deployment must not split into two farms because one writes
// /v3 and the other does not, or because one reaches it over http.
func TestKeystoneURLNormalizesToOneIdentity(t *testing.T) {
	same := []string{
		"https://172.16.0.245:5000",
		"https://172.16.0.245:5000/v3",
		"http://172.16.0.245:5000/",
		`"https://172.16.0.245:5000/v3/"`,
	}
	want := normalizeKeystoneURL(same[0])
	if want == "" {
		t.Fatal("the base endpoint did not normalize at all")
	}
	for _, raw := range same[1:] {
		if got := normalizeKeystoneURL(raw); got != want {
			t.Errorf("normalizeKeystoneURL(%q) = %q, want %q — one deployment split in two", raw, got, want)
		}
	}
}

// Different deployments must stay apart.
func TestKeystoneURLKeepsDeploymentsApart(t *testing.T) {
	a := normalizeKeystoneURL("http://192.168.201.130:5000")
	b := normalizeKeystoneURL("http://192.168.201.90:5000")
	if a == b || a == "" || b == "" {
		t.Errorf("two deployments collapsed into one: %q vs %q", a, b)
	}
}

func writeConf(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
}
