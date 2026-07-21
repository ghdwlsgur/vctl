package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/ghdwlsgur/vctl/internal/store"
)

func TestRenderInventoryOmitsRuntimeStatus(t *testing.T) {
	now := time.Now()
	servers := []store.ServerWithStatus{
		{
			Server: store.Server{Hostname: "host-a", IP: "192.0.2.1", User: "root", DC: "seoul", LastSeenUp: &now},
			Status: &store.ServerStatus{LastSeenAt: now, AgentVersion: "test"},
		},
		{Server: store.Server{Hostname: "host-b", IP: "192.0.2.2", User: "root", DC: "seoul"}},
	}

	var out strings.Builder
	renderInventory(&out, servers)
	got := out.String()
	for _, unwanted := range []string{" up", "down", "stale", "seen ", "●", "○"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("inventory contains runtime status %q:\n%s", unwanted, got)
		}
	}
	for _, wanted := range []string{"host-a", "host-b", "· 2 hosts", "2 hosts"} {
		if !strings.Contains(got, wanted) {
			t.Errorf("inventory missing %q:\n%s", wanted, got)
		}
	}
}
