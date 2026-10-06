package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/nodeaccess"
)

func nodeAccessEnrollVMCmd() *cobra.Command {
	var gateway, tokenFile, instanceUUID, caFile, certFile, keyFile string
	cmd := &cobra.Command{
		Use:   "enroll-vm",
		Short: "Create a VM-local key and enroll it with the access gateway",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if gateway == "" || tokenFile == "" || instanceUUID == "" {
				return fmt.Errorf("--gateway, --token-file, and --instance-id are required")
			}
			return nodeaccess.EnrollVM(cmd.Context(), gateway, tokenFile, instanceUUID, caFile, certFile, keyFile)
		},
	}
	cmd.Flags().StringVar(&gateway, "gateway", os.Getenv("VCTL_ACCESS_GATEWAY"), "HTTPS access gateway URL")
	cmd.Flags().StringVar(&tokenFile, "token-file", "/etc/vctl/session-agent/enrollment-token", "root-only short-lived enrollment grant")
	cmd.Flags().StringVar(&instanceUUID, "instance-id", "", "Nova instance UUID")
	cmd.Flags().StringVar(&caFile, "ca", "/etc/vctl/session-agent/gateway-ca.crt", "gateway CA bundle")
	cmd.Flags().StringVar(&certFile, "cert", "/var/lib/vctl-session-agent/node.crt", "where to store the VM certificate")
	cmd.Flags().StringVar(&keyFile, "key", "/var/lib/vctl-session-agent/node.key", "where to store the VM private key")
	return cmd
}
