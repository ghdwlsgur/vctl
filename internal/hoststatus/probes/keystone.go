package probes

import (
	"bufio"
	"net/url"
	"os"
	"strings"
)

// Which deployment a host belongs to is answered locally by one fact: the
// Keystone every service on it authenticates against.
//
// It is read out of nova.conf, which is present on controllers and compute
// nodes alike — verified across this fleet, where a controller and two compute
// nodes all name https://172.16.0.245:5000 and are in fact one deployment.
//
// # Reading a file that also holds secrets
//
// nova.conf carries service passwords. This scans it a line at a time and keeps
// only `auth_url`; no other key is parsed, the file is never held whole, and
// the value is rejected unless it is an http(s) URL. That last check is the one
// that matters — it means a mangled or unexpected line cannot become a
// "deployment id" that then gets written to the inventory and rendered.
//
// The alternative was admin-openrc.sh, which is worse on every count: it exists
// only on controllers, and OS_AUTH_URL sits two lines from OS_PASSWORD.
var keystoneConfPaths = []string{
	"/etc/kolla/nova-compute/nova.conf",
	"/etc/kolla/nova-conductor/nova.conf",
	"/etc/kolla/nova-api/nova.conf",
	"/etc/nova/nova.conf",
}

// maxConfScan bounds how much of a config file is read. A wedged or hostile
// file must not pull an unbounded amount into a process capped at 48M.
const maxConfScan = 4 << 20

// keystoneURL returns the Keystone this host authenticates against.
//
// auth_url appears in several sections of nova.conf ([keystone_authtoken],
// [neutron], [placement]) and they all name the same Keystone, so the first is
// enough.
func (p *OpenStack) keystoneURL() string {
	for _, path := range keystoneConfPaths {
		if v := scanForAuthURL(p.path(path)); v != "" {
			return v
		}
	}
	return ""
}

func scanForAuthURL(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	var read int
	for sc.Scan() {
		line := sc.Text()
		if read += len(line); read > maxConfScan {
			return ""
		}
		key, value, ok := strings.Cut(line, "=")
		// Anything that is not auth_url is dropped here, before it is looked at
		// any further. The passwords in this file are never parsed.
		if !ok || strings.TrimSpace(key) != "auth_url" {
			continue
		}
		if v := normalizeKeystoneURL(strings.TrimSpace(value)); v != "" {
			return v
		}
	}
	return ""
}

// normalizeKeystoneURL reduces a Keystone endpoint to the identity of the
// deployment behind it, and refuses anything that is not one.
//
// The path is dropped because /v3 and / name the same Keystone, and two hosts
// of one deployment writing different suffixes would otherwise split into two
// farms. The scheme is dropped for the same reason: a deployment reached over
// http from one node and https from another is still one deployment.
func normalizeKeystoneURL(raw string) string {
	raw = strings.Trim(raw, `"'`)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	// Only an http(s) URL with a host. This is what stops a stray line in a
	// config file from becoming a deployment id.
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return ""
	}
	return u.Host
}
