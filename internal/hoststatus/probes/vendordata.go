package probes

import (
	"bufio"
	"os"
	"strings"

	"github.com/ghdwlsgur/vctl/internal/hoststatus"
)

// Whether a farm hands the vctl SSH CA to the VMs it creates.
//
// The answer is two files on the host and one question about which service
// reads them, and getting that last part wrong is not hypothetical: on one farm
// the config sat in nova-api for a month while nova-metadata was the service
// answering 169.254.169.254. vendor_data.json returned {} the whole time and
// meta_data.json returned real data, so nothing looked broken. New VMs simply
// did not trust the CA, and nobody found out until somebody tried to reach one.
//
// This probe exists so the fleet listing can answer that without anyone signing
// a metadata request by hand.
//
// # What it reads
//
// nova.conf carries service passwords. As in keystoneURL, this scans a line at
// a time, keeps only vendordata_jsonfile_path, never holds the file whole, and
// stats the payload rather than reading it — the CA public key is not a secret,
// but there is no reason for a status probe to carry it around.

// vendordataKey is the config key that decides whether nova serves any of this.
const vendordataKey = "vendordata_jsonfile_path"

// metadataServiceDirs are the Kolla config directories that can hold the
// service answering instance metadata, most specific first.
//
// nova-metadata is its own service on newer releases and does not exist at all
// on older ones, where nova-api serves both APIs from one apache config — a
// vhost on 8774 and another on 8775. Measured across the deploy hosts here:
// kolla-ansible 17.3.1, 18.1.0 and 18.8.0 have no nova-metadata in
// nova_services; 20.2.0 and 20.4.0 do. So the answer is derived from what is on
// the host rather than assumed, which is the same mistake this probe reports.
var metadataServiceDirs = []string{
	"/etc/kolla/nova-metadata",
	"/etc/kolla/nova-api",
}

// vendordataState reports whether this host's metadata service hands out the
// SSH CA, and which service that is.
//
// Empty state means the host serves no metadata API, so the question does not
// apply to it — a compute node is not missing anything by not having this.
//
// It reads the deployed config, not the running container. A farm whose config
// was regenerated but whose container has not been restarted yet reads as "on"
// here while still serving {}. That gap is real and deliberate: the alternative
// is signing a metadata request, which needs the neutron proxy secret, and a
// status probe has no business holding that.
func (p *OpenStack) vendordataState() (state, service string) {
	dir := ""
	for _, d := range metadataServiceDirs {
		if fi, err := os.Stat(p.path(d)); err == nil && fi.IsDir() {
			dir = d
			break
		}
	}
	if dir == "" {
		return "", ""
	}
	service = strings.TrimPrefix(dir, "/etc/kolla/")

	configured := confNamesVendordata(p.path(dir + "/nova.conf"))
	present := nonEmptyFile(p.path(dir + "/vendordata.json"))

	switch {
	case configured && present:
		return hoststatus.VendordataOn, service
	case configured:
		return hoststatus.VendordataNoFile, service
	case present:
		return hoststatus.VendordataNoConfig, service
	default:
		return hoststatus.VendordataOff, service
	}
}

// confNamesVendordata reports whether a nova.conf sets vendordata_jsonfile_path.
//
// Only that key is parsed, and only its presence is kept. The path it names is
// a container path (/etc/nova/vendordata.json) that says nothing a reader here
// could use, and the file this host holds is the one Kolla will mount into it.
func confNamesVendordata(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()

	read := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		// Bounded the same way keystoneURL bounds it: a wedged or hostile file
		// must not pull an unbounded amount into a process capped at 48M.
		if read += len(line); read > maxConfScan {
			return false
		}
		key, _, ok := strings.Cut(strings.TrimSpace(line), "=")
		// Anything that is not this one key is dropped before it is looked at
		// any further. The passwords in this file are never parsed.
		if !ok || strings.TrimSpace(key) != vendordataKey {
			continue
		}
		return true
	}
	return false
}

// nonEmptyFile is the check that matters for the payload: a zero-byte file
// deploys, mounts, parses as nothing, and grants nothing.
func nonEmptyFile(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().IsRegular() && fi.Size() > 0
}
