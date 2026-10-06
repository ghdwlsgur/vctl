package cli

import (
	"context"
	"os"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/nodeaccess"
)

func connectNodeShell(ctx context.Context, gateway string, a *app.App, target string) error {
	return nodeaccess.ConnectShell(ctx, gateway, a.Vault.Token(), target, os.Stdin, os.Stdout)
}
