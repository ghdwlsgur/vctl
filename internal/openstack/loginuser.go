package openstack

import "strings"

// DefaultVMUser is what a VM connection tries first when nobody named a user.
//
// root rather than a distro account, because this fleet's images are built
// with root enabled for the SSH CA and the operators think in root. The distro
// account is the fallback, not the default: it exists on exactly the machines
// whose image disabled root, and the image name says which those are.
const DefaultVMUser = "root"

// LoginCandidates is the order a VM connection tries login users in when the
// operator did not name one: root, then the user the image name implies, then
// the configured default. Deduplicated so a candidate is never dialed twice;
// an unknown image simply contributes nothing.
//
// The walk stops at the first attempt that is not an authentication failure —
// a network error or a success is an answer about the machine, not the user.
func LoginCandidates(imageName, configured string) []string {
	out := []string{DefaultVMUser}
	for _, u := range []string{ImageLoginUser(imageName), configured} {
		if u != "" && !contains(out, u) {
			out = append(out, u)
		}
	}
	return out
}

// ImageLoginUser is the cloud-image login account an image name implies, or
// empty when the name says nothing. Matching is on substrings of the lowered
// name because image names here are free text ("Ubuntu-22.04-cloud",
// "rocky9-gpu-base") with the distro somewhere inside.
//
// The table is the well-known cloud-image accounts, not a guess per distro
// family: Rocky and CentOS both descend from RHEL and all three ship different
// users.
func ImageLoginUser(imageName string) string {
	name := strings.ToLower(imageName)
	for _, m := range imageUsers {
		if strings.Contains(name, m.marker) {
			return m.user
		}
	}
	return ""
}

// imageUsers is ordered: earlier markers win, so "rocky" is decided before a
// name like "rocky-on-centos-base" could reach a later entry.
var imageUsers = []struct{ marker, user string }{
	{"ubuntu", "ubuntu"},
	{"rocky", "rocky"},
	{"centos", "centos"},
	{"debian", "debian"},
	{"fedora", "fedora"},
	{"alma", "almalinux"},
	{"rhel", "cloud-user"},
	{"opensuse", "opensuse"},
	{"cirros", "cirros"},
	{"vyos", "vyos"},
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
