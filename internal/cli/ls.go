package cli

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/ui"
)

func lsCmd() *cobra.Command {
	var dc string
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List accessible inventory hosts",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			a, err := newApp()
			if err != nil {
				return err
			}
			st, err := a.OpenStore(ctx, false)
			if err != nil {
				return err
			}
			defer st.Close()

			servers, err := st.List(ctx, dc)
			if err != nil {
				return err
			}
			if len(servers) == 0 {
				ui.Warnf(os.Stderr, "inventory is empty. Run 'vctl sync' first.")
				return nil
			}
			rows := make([][]string, 0, len(servers))
			for _, s := range servers {
				status := ui.Muted("down")
				if s.LastSeenUp != nil {
					status = ui.OK("up")
				}
				jump := s.JumpVia
				if jump == "" {
					jump = ui.Muted("direct")
				}
				rows = append(rows, []string{s.Hostname, s.IP, s.User, s.DC, jump, status})
			}
			ui.Section(os.Stdout, "inventory")
			return ui.Table(os.Stdout, []string{"host", "ip", "user", "dc", "jump", "status"}, rows)
		},
	}
	cmd.Flags().StringVar(&dc, "dc", "", "DC filter, for example incheon or seoul-onprem")
	return cmd
}
