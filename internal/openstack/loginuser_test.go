package openstack

import (
	"reflect"
	"testing"
)

// The image name is free text with the distro somewhere inside; the account it
// implies is the well-known cloud-image one, not a guess per family — Rocky,
// CentOS and RHEL are one lineage shipping three different users.
func TestImageLoginUser(t *testing.T) {
	for _, tc := range []struct{ image, want string }{
		{"Ubuntu-22.04-cloud", "ubuntu"},
		{"rocky9-gpu-base", "rocky"},
		{"CentOS-Stream-9", "centos"},
		{"debian-12-genericcloud", "debian"},
		{"AlmaLinux-9", "almalinux"},
		{"rhel-9.4-x86_64-kvm", "cloud-user"},
		{"vyos-1.5-stream-2026.03", "vyos"},
		{"gitlab-appliance", ""}, // says nothing about the OS account
		{"", ""},
	} {
		if got := ImageLoginUser(tc.image); got != tc.want {
			t.Errorf("ImageLoginUser(%q) = %q, want %q", tc.image, got, tc.want)
		}
	}
}

// root leads, the image account follows, the configured default closes —
// deduplicated, so a candidate is never dialed (and audited) twice.
func TestLoginCandidates(t *testing.T) {
	if got := LoginCandidates("Ubuntu-22.04", "ubuntu"); !reflect.DeepEqual(got, []string{"root", "ubuntu"}) {
		t.Errorf("ubuntu image: %v", got)
	}
	if got := LoginCandidates("rocky9-base", "ubuntu"); !reflect.DeepEqual(got, []string{"root", "rocky", "ubuntu"}) {
		t.Errorf("rocky image: %v", got)
	}
	// An unknown image contributes nothing; the walk still has somewhere to go.
	if got := LoginCandidates("", "ubuntu"); !reflect.DeepEqual(got, []string{"root", "ubuntu"}) {
		t.Errorf("unknown image: %v", got)
	}
}
