package cli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	deploynode "github.com/ghdwlsgur/vctl/deploy/node"
	"github.com/ghdwlsgur/vctl/internal/access"
	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/cli/internal/cmdkit"
	openstackcli "github.com/ghdwlsgur/vctl/internal/cli/openstack"
	"github.com/ghdwlsgur/vctl/internal/config"
	"github.com/ghdwlsgur/vctl/internal/nodeaccess"
	osdomain "github.com/ghdwlsgur/vctl/internal/openstack"
	"github.com/ghdwlsgur/vctl/internal/sshc"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/ui"
	"github.com/ghdwlsgur/vctl/internal/vaultc"
)

func nodeAccessCmd(env cmdkit.Env) *cobra.Command {
	var gateway, service, lines string
	cmd := &cobra.Command{
		Use:   "node-access <host-or-vm-uuid> <operation>",
		Short: "Access a node through the outbound session gateway",
		Long: `Requests a fixed, read-only operation from a node with vctl-session-agent.
The target may be a physical inventory hostname or an active OpenStack VM UUID.
The gateway revalidates the Vault token, node inventory, and access grant.
The shell operation opens a PTY and requires the separate node-access-shell grant.`,
		Args: cobra.ExactArgs(2),
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			if len(args) == 0 {
				return cmdkit.CompleteInventoryHost(env)(cmd, args, toComplete)
			}
			if len(args) == 1 {
				return []string{"host-status", "containers", "service-status", "service-journal", "shell"}, cobra.ShellCompDirectiveNoFileComp
			}
			return nil, cobra.ShellCompDirectiveNoFileComp
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := env.App()
			if err != nil {
				return err
			}
			if gateway == "" {
				gateway = a.Cfg.AccessGateway
			}
			if gateway == "" {
				return fmt.Errorf("set access_gateway or pass --gateway")
			}
			if args[1] == "shell" {
				if err := a.EnsureLogin(cmd.Context()); err != nil {
					return err
				}
				return connectNodeShell(cmd.Context(), gateway, a, args[0])
			}
			requestID, err := newRequestID()
			if err != nil {
				return err
			}
			operation, params, err := nodeOperation(args[1], service, lines)
			if err != nil {
				return err
			}
			request := nodeaccess.Request{
				Version:   nodeaccess.ProtocolVersion,
				ID:        requestID,
				Operation: operation,
				Params:    params,
				Deadline:  time.Now().Add(90 * time.Second),
			}
			if err := request.Validate(time.Now()); err != nil {
				return err
			}
			if err := a.EnsureLogin(cmd.Context()); err != nil {
				return err
			}
			result, err := submitNodeRequest(cmd.Context(), gateway, a, args[0], request)
			if err != nil {
				return err
			}
			if result.Error != "" {
				return fmt.Errorf("node operation failed: %s", result.Error)
			}
			_, err = fmt.Fprint(os.Stdout, result.Output)
			return err
		},
	}
	cmd.Flags().StringVar(&gateway, "gateway", os.Getenv("VCTL_ACCESS_GATEWAY"), "HTTPS access gateway URL")
	cmd.Flags().StringVar(&service, "service", "", "systemd unit for service-status/service-journal")
	cmd.Flags().StringVar(&lines, "lines", "100", "journal lines (1-500) for service-journal")
	cmd.AddCommand(cmdkit.Gate(nodeAccessInstallCmd(env), "node-access"))
	cmd.AddCommand(cmdkit.Gate(nodeAccessInstallVMCmd(env), "node-access-shell"))
	return cmd
}

func nodeAccessInstallCmd(env cmdkit.Env) *cobra.Command {
	var binaryPath string
	cmd := &cobra.Command{
		Use:   "install <inventory-hostname>",
		Short: "Install the node-access agent with a host-only renewable identity",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			a, err := env.App()
			if err != nil {
				return err
			}
			if err := a.EnsureLogin(ctx); err != nil {
				return err
			}
			host, err := installTarget(ctx, a, args[0])
			if err != nil {
				return err
			}
			if host.User != "root" {
				return fmt.Errorf("node-access install needs root SSH for %s, inventory user is %q", host.Hostname, host.User)
			}
			identity, err := a.Vault.EnsureNodeAccessIdentity(ctx, host.Hostname, a.Cfg.AppRoleMount)
			if err != nil {
				return err
			}
			bin, err := agentBinary(ctx, binaryPath)
			if err != nil {
				return err
			}
			checksum := sha256.Sum256(bin)
			shaHex := hex.EncodeToString(checksum[:])
			target := &sshc.Target{Name: host.Hostname, Addr: net.JoinHostPort(host.IP, installPort(host)), User: host.User, Role: a.Cfg.CARole}
			connector := cmdkit.NewConnector(a)
			req := access.Request{Target: target, HostKey: access.HostKeyAcceptNew}
			push := fmt.Sprintf("umask 022 && cat > /usr/local/bin/.vctl-agent.new && chmod 0755 /usr/local/bin/.vctl-agent.new && echo '%s  /usr/local/bin/.vctl-agent.new' | sha256sum -c - >/dev/null && mv -f /usr/local/bin/.vctl-agent.new /usr/local/bin/vctl-agent", shaHex)
			if _, err := connector.ExecuteWithInput(ctx, req, push, 0, bytes.NewReader(bin)); err != nil {
				return fmt.Errorf("push vctl-agent: %w", err)
			}
			bundle, err := nodeAccessBundle(host.Hostname, a.Cfg.AccessGateway, a.Cfg.VaultAddr, identity)
			if err != nil {
				return err
			}
			remote := "install -d -m 0700 /etc/vctl/session-agent /var/lib/vctl-session-agent && tar -xz -C / && chmod 0600 /etc/vctl/session-agent/role-id /etc/vctl/session-agent/secret-id /etc/vctl/session-agent/gateway-ca.crt /etc/vctl/session-agent.env /var/lib/vctl-session-agent/node.crt /var/lib/vctl-session-agent/node.key && systemctl daemon-reload && systemctl enable --now vctl-session-agent"
			if _, err := connector.ExecuteWithInput(ctx, req, remote, 0, bytes.NewReader(bundle)); err != nil {
				return fmt.Errorf("install session-agent on %s: %w", host.Hostname, err)
			}
			ui.Successf(os.Stderr, "node-access agent installed on %s; its certificate renews automatically", host.Hostname)
			return nil
		},
	}
	cmd.Flags().StringVar(&binaryPath, "binary", "", "push this local Linux agent binary instead of downloading the release")
	return cmd
}

func nodeAccessInstallVMCmd(env cmdkit.Env) *cobra.Command {
	var binaryPath, farm string
	var assumeLinux, allowStale bool
	cmd := &cobra.Command{
		Use:   "install-vm <nova-uuid>",
		Short: "Install the outbound access agent in an active Linux VM",
		Long: `Installs a VM-specific mTLS identity and vctl-session-agent over the
existing audited Vault SSH-certificate path. The VM must already trust the vctl
SSH CA and the selected login account must have passwordless sudo. When the
farm API is unreachable, --allow-stale permits using an old inventory record;
the installer still verifies the guest OS and passwordless sudo over SSH first.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, ok := access.NovaID(args[0])
			if !ok {
				return fmt.Errorf("install-vm needs a Nova UUID")
			}
			ctx := cmd.Context()
			a, err := env.App()
			if err != nil {
				return err
			}
			if err := a.EnsureLogin(ctx); err != nil {
				return err
			}
			return env.WithStore(ctx, false, func(a *app.App, st *store.Store) error {
				vm, err := lookupVM(ctx, a, st, id, farm)
				if err != nil {
					return err
				}
				if err := checkVMCurrent(vm, id, allowStale); err != nil {
					return err
				}
				if allowStale && (vm.ObservedAt.IsZero() || time.Since(vm.ObservedAt) > 3*time.Hour) {
					ui.Warnf(os.Stderr, "using possibly stale inventory for %s; verifying the guest over SSH before installation", openstackcli.NameOrID(vm))
				}
				if !strings.EqualFold(vm.Status, "ACTIVE") || vm.MissingSince != nil {
					return fmt.Errorf("VM %s is not active", openstackcli.NameOrID(vm))
				}
				image := strings.ToLower(vm.ImageName)
				if strings.Contains(image, "windows") || strings.Contains(image, "amphora") {
					return fmt.Errorf("image %q is not a supported Linux guest", vm.ImageName)
				}
				if vm.ImageName == "" && !assumeLinux {
					return fmt.Errorf("VM image is unknown; confirm it is Linux with --assume-linux")
				}
				connector := cmdkit.NewConnector(a)
				var selected *sshc.Target
				_, err = access.TryLoginUsers(osdomain.LoginCandidates(vm.ImageName, a.Cfg.SSHDefaultUser), func(user string) error {
					target, err := vmTarget(ctx, a, st, vm, user)
					if err != nil {
						return err
					}
					preflight := "id -un && sudo -n true && test -s /etc/os-release && cat /etc/os-release"
					result, err := connector.Execute(ctx, access.Request{Target: target, HostKey: access.HostKeyAcceptNew}, sudoCommand(user, preflight), 0)
					if err != nil {
						return err
					}
					if result.ExitCode != 0 {
						return fmt.Errorf("SSH preflight as %s failed (login, passwordless sudo, or /etc/os-release): %s", user, strings.TrimSpace(result.Stderr))
					}
					osID := osReleaseID(result.Stdout)
					if osID == "" || !vmImageMatchesOS(vm.ImageName, osID) {
						return fmt.Errorf("SSH target reports OS id %q, which does not match Linux image %q", osID, vm.ImageName)
					}
					selected = target
					return nil
				}, func(rejectedUser, next string) {
					ui.Warnf(os.Stderr, "%s rejected login user %q — trying %q", openstackcli.NameOrID(vm), rejectedUser, next)
				})
				if err != nil {
					return fmt.Errorf("could not verify VM bootstrap prerequisites: %w", err)
				}
				gatewayHost, gatewayIP, err := resolveAccessGateway(ctx, a.Cfg.AccessGateway)
				if err != nil {
					return err
				}
				identity, err := a.Vault.EnsureNodeAccessIdentity(ctx, id, a.Cfg.AppRoleMount)
				if err != nil {
					return err
				}
				bin, err := agentBinary(ctx, binaryPath)
				if err != nil {
					return err
				}
				digest := sha256.Sum256(bin)
				digestHex := hex.EncodeToString(digest[:])
				push := fmt.Sprintf("umask 022 && cat > /usr/local/bin/.vctl-agent.new && chmod 0755 /usr/local/bin/.vctl-agent.new && echo '%s  /usr/local/bin/.vctl-agent.new' | sha256sum -c - >/dev/null && mv -f /usr/local/bin/.vctl-agent.new /usr/local/bin/vctl-agent", digestHex)
				command := sudoCommand(selected.User, push)
				result, err := connector.ExecuteWithInput(ctx, access.Request{Target: selected, HostKey: access.HostKeyAcceptNew}, command, 0, bytes.NewReader(bin))
				if err != nil {
					return fmt.Errorf("push agent to %s: %w", openstackcli.NameOrID(vm), err)
				}
				if result.ExitCode != 0 {
					return fmt.Errorf("push agent to %s failed: %s", openstackcli.NameOrID(vm), strings.TrimSpace(result.Stderr))
				}
				bundle, err := nodeAccessBundleWithUnit(id, a.Cfg.AccessGateway, a.Cfg.VaultAddr, identity, "vctl-vm-session-agent.service", deploynode.VMSessionAgentUnit)
				if err != nil {
					return err
				}
				remote := "install -d -m 0700 /etc/vctl/session-agent /var/lib/vctl-session-agent && tar -xz -C / && chmod 0600 /etc/vctl/session-agent/role-id /etc/vctl/session-agent/secret-id /etc/vctl/session-agent/gateway-ca.crt /etc/vctl/session-agent.env /var/lib/vctl-session-agent/node.crt /var/lib/vctl-session-agent/node.key && " + gatewayHostsCommand(gatewayHost, gatewayIP) + "systemctl daemon-reload && systemctl enable vctl-vm-session-agent.service && systemctl restart vctl-vm-session-agent.service"
				command = sudoCommand(selected.User, remote)
				result, err = connector.ExecuteWithInput(ctx, access.Request{Target: selected, HostKey: access.HostKeyAcceptNew}, command, 0, bytes.NewReader(bundle))
				if err != nil {
					return fmt.Errorf("install session-agent in %s: %w", openstackcli.NameOrID(vm), err)
				}
				if result.ExitCode != 0 {
					return fmt.Errorf("install session-agent in %s failed: %s", openstackcli.NameOrID(vm), strings.TrimSpace(result.Stderr))
				}
				ui.Successf(os.Stderr, "node-access agent installed in VM %s (%s)", openstackcli.NameOrID(vm), id)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&binaryPath, "binary", "", "push this local Linux agent binary instead of downloading the release")
	cmd.Flags().StringVar(&farm, "farm", "", "deployment when this UUID exists in more than one farm")
	cmd.Flags().BoolVar(&assumeLinux, "assume-linux", false, "proceed when the inventory has no image name; use only after confirming the guest OS")
	cmd.Flags().BoolVar(&allowStale, "allow-stale", false, "use an old VM record when the farm API is unreachable; SSH preflight must still verify the guest OS and passwordless sudo")
	cmdkit.RegisterCompletion(cmd, "farm", openstackcli.CompleteFarm(env))
	return cmd
}

// resolveAccessGateway returns the current IPv4 address of the configured
// gateway hostname. Tenant VMs may use public DNS that cannot resolve the
// private SRE zone; install-vm uses this address to seed a guest-local mapping
// only when the guest resolver has no answer.
func resolveAccessGateway(ctx context.Context, raw string) (hostname, address string, err error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", "", fmt.Errorf("access gateway must be a valid https URL")
	}
	hostname = parsed.Hostname()
	if hostname == "" {
		return "", "", fmt.Errorf("access gateway URL has no hostname")
	}
	if ip := net.ParseIP(hostname); ip != nil {
		return "", "", nil
	}
	for _, r := range hostname {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '.') {
			return "", "", fmt.Errorf("invalid access gateway hostname %q", hostname)
		}
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, hostname)
	if err != nil {
		return "", "", fmt.Errorf("resolve access gateway %s: %w", hostname, err)
	}
	for _, candidate := range ips {
		if v4 := candidate.IP.To4(); v4 != nil {
			return hostname, v4.String(), nil
		}
	}
	if len(ips) > 0 {
		return hostname, ips[0].IP.String(), nil
	}
	return "", "", fmt.Errorf("access gateway %s resolved to no addresses", hostname)
}

// gatewayHostsCommand preserves TLS SNI and certificate hostname verification
// when a VM's resolver cannot resolve the private access-gateway domain.
func gatewayHostsCommand(hostname, address string) string {
	if hostname == "" || address == "" {
		return ""
	}
	return fmt.Sprintf("if ! getent hosts %s >/dev/null 2>&1; then printf '%%s %%s # vctl access gateway\\n' %s %s >> /etc/hosts; fi && ",
		strconv.Quote(hostname), strconv.Quote(address), strconv.Quote(hostname))
}

func sudoCommand(user, command string) string {
	if user == "root" {
		return command
	}
	return "sudo -n sh -c " + strconv.Quote(command)
}

func osReleaseID(contents string) string {
	for _, line := range strings.Split(contents, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ID=") {
			return strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "ID=")), "\"'")
		}
	}
	return ""
}

func vmImageMatchesOS(imageName, osID string) bool {
	image := strings.ToLower(imageName)
	for _, distro := range []string{"rocky", "ubuntu", "debian", "centos", "almalinux", "rhel", "oracle", "fedora", "opensuse"} {
		if strings.Contains(image, distro) {
			return osID == distro
		}
	}
	return osID != ""
}

func nodeAccessBundle(hostname, gateway, vaultAddr string, identity vaultc.NodeAccessIdentity) ([]byte, error) {
	return nodeAccessBundleWithUnit(hostname, gateway, vaultAddr, identity, "vctl-session-agent.service", deploynode.SessionAgentUnit)
}

func nodeAccessBundleWithUnit(hostname, gateway, vaultAddr string, identity vaultc.NodeAccessIdentity, unitName, unitContent string) ([]byte, error) {
	if gateway == "" || vaultAddr == "" {
		return nil, fmt.Errorf("access gateway and Vault addresses are required")
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	files := map[string][]byte{
		"etc/vctl/session-agent/role-id":        []byte(identity.RoleID + "\n"),
		"etc/vctl/session-agent/secret-id":      []byte(identity.SecretID + "\n"),
		"etc/vctl/session-agent/gateway-ca.crt": config.SRERootCA,
		"var/lib/vctl-session-agent/node.crt":   identity.CertificatePEM,
		"var/lib/vctl-session-agent/node.key":   identity.PrivateKeyPEM,
		"etc/vctl/session-agent.env":            []byte(fmt.Sprintf("VCTL_ACCESS_GATEWAY=%s\nVAULT_ADDR=%s\nVCTL_RENEW_PKI_MOUNT=pki_sre_int\nVCTL_RENEW_PKI_ROLE=vctl-node-access-%s\nVCTL_RENEW_COMMON_NAME=%s.sre.local\nVCTL_RENEW_URI_SAN=spiffe://vctl.local/node/%s\n", gateway, vaultAddr, hostname, hostname, hostname)),
		"etc/systemd/system/" + unitName:        []byte(unitContent),
	}
	for name, data := range files {
		clean := path.Clean(name)
		if clean != name || strings.HasPrefix(clean, "../") {
			return nil, fmt.Errorf("invalid bundle path %q", name)
		}
		mode := int64(0o600)
		if strings.HasSuffix(name, ".service") {
			mode = 0o644
		}
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: mode, Size: int64(len(data)), Typeflag: tar.TypeReg}); err != nil {
			return nil, err
		}
		if _, err := io.Copy(tw, bytes.NewReader(data)); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func nodeOperation(name, service, lines string) (nodeaccess.Operation, map[string]string, error) {
	switch name {
	case "host-status":
		return nodeaccess.OperationHostStatus, nil, nil
	case "containers":
		return nodeaccess.OperationContainerList, nil, nil
	case "service-status":
		if service == "" {
			return "", nil, fmt.Errorf("--service is required for service-status")
		}
		return nodeaccess.OperationServiceStatus, map[string]string{"service": service}, nil
	case "service-journal":
		if service == "" {
			return "", nil, fmt.Errorf("--service is required for service-journal")
		}
		return nodeaccess.OperationServiceJournal, map[string]string{"service": service, "lines": lines}, nil
	default:
		return "", nil, fmt.Errorf("unknown operation %q (choose host-status, containers, service-status, or service-journal)", name)
	}
}

func submitNodeRequest(ctx context.Context, gateway string, a *app.App, node string, request nodeaccess.Request) (nodeaccess.Result, error) {
	parsed, err := url.Parse(gateway)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nodeaccess.Result{}, fmt.Errorf("gateway URL must be an https URL without credentials, query, or fragment")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(config.SRERootCA) {
		return nodeaccess.Result{}, fmt.Errorf("embedded gateway CA bundle is invalid")
	}
	payload := struct {
		Node    string             `json:"node"`
		Request nodeaccess.Request `json:"request"`
	}{Node: node, Request: request}
	body, err := json.Marshal(payload)
	if err != nil {
		return nodeaccess.Result{}, err
	}
	endpoint := strings.TrimRight(parsed.String(), "/") + "/v1/sessions"
	callCtx, cancel := context.WithTimeout(ctx, time.Until(request.Deadline)+5*time.Second)
	defer cancel()
	httpRequest, err := http.NewRequestWithContext(callCtx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nodeaccess.Result{}, err
	}
	httpRequest.Header.Set("Authorization", "Bearer "+a.Vault.Token())
	httpRequest.Header.Set("Content-Type", "application/json")
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}, ForceAttemptHTTP2: true},
		Timeout:   time.Until(request.Deadline) + 5*time.Second,
	}
	defer client.CloseIdleConnections()
	response, err := client.Do(httpRequest)
	if err != nil {
		return nodeaccess.Result{}, fmt.Errorf("request node operation: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		var body struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(io.LimitReader(response.Body, 8<<10)).Decode(&body)
		if body.Error == "" {
			body.Error = response.Status
		}
		return nodeaccess.Result{}, fmt.Errorf("access gateway: %s", body.Error)
	}
	var result nodeaccess.Result
	decoder := json.NewDecoder(io.LimitReader(response.Body, 2<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return nodeaccess.Result{}, fmt.Errorf("decode node result: %w", err)
	}
	if result.Version != nodeaccess.ProtocolVersion || result.ID != request.ID {
		return nodeaccess.Result{}, fmt.Errorf("gateway returned a result that does not match the request")
	}
	return result, nil
}

func newRequestID() (string, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", fmt.Errorf("generate request id: %w", err)
	}
	return hex.EncodeToString(random[:]), nil
}
