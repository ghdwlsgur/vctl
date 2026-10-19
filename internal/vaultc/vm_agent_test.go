package vaultc

import (
	"context"
	"testing"
)

func TestSignVMAgentCSRRejectsInvalidInputBeforeVaultCall(t *testing.T) {
	client := &Client{}
	for _, input := range []struct{ instanceID, csr string }{
		{"not-a-uuid", "invalid"},
		{"01234567-89ab-cdef-0123-456789abcdef", "invalid"},
	} {
		if _, err := client.SignVMAgentCSR(context.Background(), input.instanceID, input.csr); err == nil {
			t.Errorf("SignVMAgentCSR(%q, %q) unexpectedly succeeded", input.instanceID, input.csr)
		}
	}
}

// The accessor and role come from a host's /etc/vctl, so both are checked
// before they are spliced into a Vault path.
func TestDestroySecretIDAccessorRejectsUnsafeInput(t *testing.T) {
	c := &Client{}
	for name, tc := range map[string][2]string{
		"path in role":     {"../sys/policy", "93d7f2c6-1111-2222-3333-444455556666"},
		"empty role":       {"", "93d7f2c6-1111-2222-3333-444455556666"},
		"path in accessor": {"vctl-node", "../../root"},
		"empty accessor":   {"vctl-node", ""},
	} {
		if err := c.DestroySecretIDAccessor(context.Background(), "approle", tc[0], tc[1]); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
