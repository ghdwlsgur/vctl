package store

import (
	"context"
	"fmt"
	"time"
)

type NodeAccessAuditEvent struct {
	RequestID  string
	Phase      string
	Operator   string
	Hostname   string
	TargetKind string
	Operation  string
	StartedAt  time.Time
	EndedAt    *time.Time
	Outcome    string
}

// InsertNodeAccessAudit appends lifecycle metadata for a typed node operation.
// The dedicated Vault database role has INSERT only; outputs and parameters are
// intentionally not stored in the audit row.
func (s *Store) InsertNodeAccessAudit(ctx context.Context, event NodeAccessAuditEvent) error {
	if event.RequestID == "" || event.Operator == "" || event.Hostname == "" || event.Operation == "" {
		return fmt.Errorf("node access audit requires request, operator, host, and operation")
	}
	if event.Phase != "started" && event.Phase != "finished" {
		return fmt.Errorf("invalid node access audit phase %q", event.Phase)
	}
	if event.TargetKind == "" {
		event.TargetKind = "host"
	}
	if event.TargetKind != "host" && event.TargetKind != "vm" {
		return fmt.Errorf("invalid node access target kind %q", event.TargetKind)
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO node_access_audit
			(request_id, phase, operator, hostname, target_kind, operation, started_at, ended_at, outcome)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		event.RequestID, event.Phase, event.Operator, event.Hostname, event.TargetKind,
		event.Operation, event.StartedAt, event.EndedAt, event.Outcome)
	return err
}
