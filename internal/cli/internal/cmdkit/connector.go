package cmdkit

import (
	"errors"
	"fmt"
	"os"

	"github.com/ghdwlsgur/vctl/internal/access"
	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

// NewConnector builds the SSH connector for this app: Vault signs certs and
// reports the identity, the app writes the audit row, and an audit-write failure
// is warned (never fatal). Shared by `vctl ssh` and the MCP vctl_ssh_exec tool.
func NewConnector(a *app.App) *access.Connector {
	return &access.Connector{
		Signer:   a.Vault,
		Identity: a.Vault,
		Audit:    a,
		SignTTL:  a.Cfg.SSHSign,
		OnAuditError: func(err error) {
			ui.Warnf(os.Stderr, "%s", AuditErrorMessage(err))
		},
	}
}

// AuditErrorMessage turns a failed audit write into what the operator needs to
// know: whether the record is gone or merely waiting.
//
// The distinction is the whole point of the spool. Reporting a queued record as
// "not recorded" would tell someone their access left no trace at the exact
// moment it did — and would push them to go re-record it by hand.
func AuditErrorMessage(err error) string {
	var spooled *app.SpooledError
	if errors.As(err, &spooled) {
		return fmt.Sprintf("audit database unreachable — access record queued locally (%d pending), "+
			"it flushes on the next successful write", spooled.Pending)
	}
	return fmt.Sprintf("access log not recorded: %v", err)
}
