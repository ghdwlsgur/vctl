package cli

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

func lsCmd() *cobra.Command {
	var dc string
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "접속 가능한 서버 목록",
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
				fmt.Fprintln(os.Stderr, "인벤토리가 비어 있습니다. 'vctl sync' 를 먼저 실행하세요.")
				return nil
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
			fmt.Fprintln(w, "HOST\tIP\tUSER\tDC\tJUMP\tSTATUS")
			for _, s := range servers {
				status := "-"
				if s.LastSeenUp != nil {
					status = "up"
				}
				jump := s.JumpVia
				if jump == "" {
					jump = "-"
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", s.Hostname, s.IP, s.User, s.DC, jump, status)
			}
			return w.Flush()
		},
	}
	cmd.Flags().StringVar(&dc, "dc", "", "DC 필터 (incheon | seoul-onprem)")
	return cmd
}
