package audit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ghdwlsgur/vctl/internal/store"
)

// fakeConn is an open audit connection that records only whether it was closed.
// Nothing here calls through it; what these tests are about is which credential
// was asked for and whose job it is to close what.
type fakeConn struct{ closed int }

func (c *fakeConn) Close() { c.closed++ }

func (*fakeConn) AccessLog(context.Context, int, string, string, string) ([]store.AccessEntry, error) {
	return nil, nil
}
func (*fakeConn) ListSessions(context.Context, string, int) ([]store.AuditSession, error) {
	return nil, nil
}
func (*fakeConn) SessionTimeline(context.Context, string, int) ([]store.AuditSession, map[int64][]store.KernelEvent, error) {
	return nil, nil, nil
}
func (*fakeConn) AuditFootprint(context.Context) ([]store.TableFootprint, error) { return nil, nil }
func (*fakeConn) CountKernelEventsBefore(context.Context, time.Time) (int64, error) {
	return 0, nil
}
func (*fakeConn) CountSessionsBefore(context.Context, time.Time) (int64, error) { return 0, nil }
func (*fakeConn) RecordSession(context.Context, store.AuditSession) (int64, error) {
	return 0, nil
}
func (*fakeConn) EndSession(context.Context, int64, time.Time, string) error { return nil }
func (*fakeConn) UnendedSessions(context.Context, string) ([]store.AuditSession, error) {
	return nil, nil
}
func (*fakeConn) InsertKernelEvents(context.Context, []store.KernelEvent) (int, error) {
	return 0, nil
}
func (*fakeConn) InsertKernelEventsAttributed(context.Context, []store.KernelEvent) (int, []int, error) {
	return 0, nil, nil
}
func (*fakeConn) PruneAudit(context.Context, store.AuditCutoff, int) (store.AuditPruneResult, error) {
	return store.AuditPruneResult{}, nil
}

// Each scope asks for the credential its work needs, and nothing else.
//
// The database enforces this — vctl-audit-ro cannot insert — but which role a
// command ran under used to be decided at the call site, eight times, by
// picking the right helper. Getting that wrong surfaced as a permission error
// in production rather than as a compile failure.
func TestEachScopeAsksForItsOwnCredential(t *testing.T) {
	var asked []Purpose
	conn := &fakeConn{}
	s := New(func(_ context.Context, p Purpose) (Conn, error) {
		asked = append(asked, p)
		return conn, nil
	})

	if err := s.Reading(context.Background(), func(Reader) error { return nil }); err != nil {
		t.Fatalf("Reading: %v", err)
	}
	if err := s.Ingesting(context.Background(), func(Ingestor) error { return nil }); err != nil {
		t.Fatalf("Ingesting: %v", err)
	}
	if err := s.Pruning(context.Background(), func(Pruner) error { return nil }); err != nil {
		t.Fatalf("Pruning: %v", err)
	}
	if len(asked) != 3 || asked[0] != Read || asked[1] != Ingest || asked[2] != Prune {
		t.Errorf("credentials asked for = %v, want [Read Ingest Prune]", asked)
	}
}

// A dynamic credential's lease should live exactly as long as the work. Eight
// call sites each had their own defer to get wrong; now there is one.
func TestTheConnectionIsClosedWhicheverWayTheWorkEnds(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{{"work succeeded", nil}, {"work failed", errors.New("query failed")}} {
		t.Run(tc.name, func(t *testing.T) {
			conn := &fakeConn{}
			s := New(func(context.Context, Purpose) (Conn, error) { return conn, nil })

			err := s.Reading(context.Background(), func(Reader) error { return tc.err })
			if !errors.Is(err, tc.err) {
				t.Errorf("err = %v, want %v", err, tc.err)
			}
			if conn.closed != 1 {
				t.Errorf("closed %d times, want exactly once — a lease outliving its command is a "+
					"credential nobody is holding", conn.closed)
			}
		})
	}
}

// A command that could not get a credential has not read anything, and running
// the work anyway would report an empty audit log as an answer.
func TestWorkDoesNotRunWhenTheCredentialIsRefused(t *testing.T) {
	want := errors.New("permission denied")
	s := New(func(context.Context, Purpose) (Conn, error) { return nil, want })

	var ran bool
	err := s.Reading(context.Background(), func(Reader) error { ran = true; return nil })
	if !errors.Is(err, want) {
		t.Errorf("err = %v, want the refusal", err)
	}
	if ran {
		t.Error("the work ran without a credential")
	}
}

// The store satisfies both scopes, which is what lets the adapter hand one over
// without the scopes widening to fit it.
func TestTheRealStoreSatisfiesTheScopes(t *testing.T) {
	var _ Conn = (*store.Store)(nil)
	var _ Reader = (*store.Store)(nil)
	var _ Ingestor = (*store.Store)(nil)
	var _ Pruner = (*store.Store)(nil)
}
