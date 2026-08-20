package app

import (
	"context"
	"strings"
	"testing"

	"github.com/ghdwlsgur/vctl/internal/config"
)

func TestOpenStoreRejectsAnUnknownPurposeBeforeOpeningAnything(t *testing.T) {
	a := testApp(t, &config.Config{
		LocalDBDSN: "postgres://nobody@127.0.0.1:1/none?sslmode=disable",
	})

	st, err := a.OpenStore(context.Background(), Purpose(1<<15))
	if st != nil {
		st.Close()
		t.Fatal("an unknown database purpose opened a store")
	}
	if err == nil || !strings.Contains(err.Error(), "unknown database purpose") {
		t.Fatalf("unknown purpose error = %v", err)
	}
}

func TestEveryDatabasePurposeMapsToARole(t *testing.T) {
	a := testApp(t, &config.Config{})
	for p := Purpose(0); p < purposeCount; p++ {
		if _, err := a.roleFor(p); err != nil {
			t.Errorf("purpose %d has no role: %v", p, err)
		}
	}
}
