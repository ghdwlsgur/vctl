package cli

import (
	"errors"
	"strings"
	"testing"

	"github.com/ghdwlsgur/vctl/internal/app"
)

// A queued record and a lost one need different words. Saying "not recorded"
// about a record sitting in the spool tells the operator their access left no
// trace when it did, and invites them to go re-record it by hand.
func TestAuditErrorMessageDistinguishesQueuedFromLost(t *testing.T) {
	cause := errors.New("dial tcp 127.0.0.1:5432: connection refused")

	queued := auditErrorMessage(&app.SpooledError{Cause: cause, Pending: 3})
	if strings.Contains(queued, "not recorded") {
		t.Errorf("a queued record was reported as lost: %q", queued)
	}
	for _, want := range []string{"queued", "3 pending", "flushes"} {
		if !strings.Contains(queued, want) {
			t.Errorf("queued message missing %q: %q", want, queued)
		}
	}

	lost := auditErrorMessage(cause)
	if !strings.Contains(lost, "not recorded") {
		t.Errorf("a genuinely lost record was not reported as lost: %q", lost)
	}
	if strings.Contains(lost, "queued") {
		t.Errorf("a lost record was reported as queued: %q", lost)
	}
}
