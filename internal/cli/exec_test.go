package cli

import (
	"fmt"
	"testing"
)

func TestChildExitCode(t *testing.T) {
	code, ok := ChildExitCode(fmt.Errorf("run: %w", &CommandExitError{Code: 17}))
	if !ok || code != 17 {
		t.Fatalf("ChildExitCode() = %d, %v; want 17, true", code, ok)
	}
	if _, ok := ChildExitCode(fmt.Errorf("other")); ok {
		t.Fatal("ChildExitCode accepted an unrelated error")
	}
}
