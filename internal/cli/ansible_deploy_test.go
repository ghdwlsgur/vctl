package cli

import (
	"os"
	"strings"
	"testing"
)

func TestAnsibleFleetRolloutHasIntegrityAndHealthGates(t *testing.T) {
	site, err := os.ReadFile("../../deploy/ansible/site.yml")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(site), "serial:") || !strings.Contains(string(site), "max_fail_percentage: 0") {
		t.Fatal("fleet play is missing bounded rollout failure gates")
	}
	present, err := os.ReadFile("../../deploy/ansible/roles/vctl_host/tasks/present.yml")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"checksum_algorithm: sha256", "systemctl is-active", "meta: flush_handlers", "vctl_host_tetragon_arch"} {
		if !strings.Contains(string(present), want) {
			t.Errorf("Ansible role is missing %q", want)
		}
	}
	if strings.Contains(string(present), "ansible_date_time") {
		t.Fatal("Ansible role still relies on deprecated top-level injected facts")
	}
	if !strings.Contains(string(present), `ansible_facts["date_time"]["epoch"]`) {
		t.Fatal("Ansible role does not read the gathered epoch through ansible_facts")
	}
}
