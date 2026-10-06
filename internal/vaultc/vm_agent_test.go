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
