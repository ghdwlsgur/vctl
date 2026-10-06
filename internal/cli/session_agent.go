package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/nodeaccess"
)

func sessionAgentCmd() *cobra.Command {
	var gatewayURL, caFile, certFile, keyFile string
	var vaultAddr, roleIDFile, secretIDFile, pkiMount, pkiRole, commonName, uriSAN, renewGateway string
	cmd := &cobra.Command{
		Use:   "session-agent",
		Short: "Maintain an outbound mTLS node access channel",
		Long: `session-agent connects outbound to the vctl access gateway using a
dedicated node certificate. It accepts only typed, read-only operations; it
does not provide a shell or use the status agent's database credentials.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if gatewayURL == "" {
				return fmt.Errorf("--gateway or VCTL_ACCESS_GATEWAY is required")
			}
			tlsConfig, err := nodeaccess.AgentTLSConfig(caFile, certFile, keyFile)
			if err != nil {
				return err
			}
			agent := &nodeaccess.SessionAgent{
				GatewayURL: gatewayURL,
				TLS:        tlsConfig,
				OnError: func(err error) {
					fmt.Fprintln(os.Stderr, "session-agent:", err)
				},
			}
			if renewGateway != "" || vaultAddr != "" || roleIDFile != "" || secretIDFile != "" || pkiMount != "" || pkiRole != "" || commonName != "" || uriSAN != "" {
				agent.Renewal = &nodeaccess.CertificateRenewer{
					GatewayURL: renewGateway,
					VaultAddr:  vaultAddr, RoleIDFile: roleIDFile, SecretFile: secretIDFile,
					PKIMount: pkiMount, PKIRole: pkiRole, CommonName: commonName, URISAN: uriSAN,
					CertFile: certFile, KeyFile: keyFile,
				}
			}
			return agent.Run(cmd.Context())
		},
	}
	cmd.Flags().StringVar(&gatewayURL, "gateway", os.Getenv("VCTL_ACCESS_GATEWAY"), "HTTPS access gateway URL")
	cmd.Flags().StringVar(&caFile, "ca", "/etc/vctl/session-agent/gateway-ca.crt", "gateway CA bundle")
	cmd.Flags().StringVar(&certFile, "cert", "/etc/vctl/session-agent/node.crt", "short-lived node client certificate")
	cmd.Flags().StringVar(&keyFile, "key", "/etc/vctl/session-agent/node.key", "node client private key")
	cmd.Flags().StringVar(&vaultAddr, "vault-addr", os.Getenv("VAULT_ADDR"), "Vault HTTPS address")
	cmd.Flags().StringVar(&roleIDFile, "vault-role-id-file", os.Getenv("VCTL_RENEW_ROLE_ID_FILE"), "node-specific Vault AppRole role id file")
	cmd.Flags().StringVar(&secretIDFile, "vault-secret-id-file", os.Getenv("VCTL_RENEW_SECRET_ID_FILE"), "node-specific Vault AppRole secret id file")
	cmd.Flags().StringVar(&pkiMount, "pki-mount", os.Getenv("VCTL_RENEW_PKI_MOUNT"), "Vault PKI mount")
	cmd.Flags().StringVar(&pkiRole, "pki-role", os.Getenv("VCTL_RENEW_PKI_ROLE"), "Vault PKI role")
	cmd.Flags().StringVar(&commonName, "common-name", os.Getenv("VCTL_RENEW_COMMON_NAME"), "certificate common name")
	cmd.Flags().StringVar(&uriSAN, "uri-san", os.Getenv("VCTL_RENEW_URI_SAN"), "certificate URI SAN")
	cmd.Flags().StringVar(&renewGateway, "renew-gateway", os.Getenv("VCTL_RENEW_GATEWAY"), "renew VM certificates through the current mTLS gateway connection")
	return cmd
}
