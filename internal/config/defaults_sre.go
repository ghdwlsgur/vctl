// This file holds INNOGRID/SRE-specific compiled defaults. The values below are
// baked into the binary for zero-setup onboarding and are organization-specific
// (vault.sre.local, DB names/roles, ca_role "sre-core", OIDC mount/role, etc.).
// They are intentionally isolated here so the org-specific surface is obvious and
// easy to fork. All values are overridable by repo-local .vctl/config.yaml and
// VCTL_*/VGO_* environment variables. The generic loader lives in config.go.
package config

import (
	"github.com/ghdwlsgur/vctl/internal/syncx"
)

// Defaults returns compiled onboarding defaults for the SRE environment.
func Defaults() *Config {
	return &Config{
		OperatorNetworks:              []string{"192.168."},
		VaultAddr:                     "https://vault.sre.local",
		AdminPolicies:                 []string{"vctl-admin", "sre-admin"},
		VaultFarmPrefix:               "kv/teams/sre",
		DNSResolver:                   "192.168.201.12:53",
		DNSKubeKVPath:                 "kv/teams/sre/vctl-dns",
		DNSGitTokenKVPath:             "kv/teams/sre/gitlab-albert",
		DNSGitBase:                    "https://gitlab.sre.local",
		DNSGitProject:                 "sre/system/internal/devtools/coredns",
		AuthMethod:                    "oidc", // people: GitLab SSO by default; --method userpass for bootstrap
		OIDCRole:                      "vctl",
		OIDCMount:                     "oidc",
		DBHost:                        "vctl-postgres.sre.local", // must match the certificate dnsName for verify-full
		DBPort:                        5432,
		DBName:                        "vctl",
		DBRoleRO:                      "vctl-ro",
		DBRoleRW:                      "vctl-rw",
		DBRoleIdentity:                "vctl-identity",
		DBRoleAuditRO:                 "vctl-audit-ro",
		DBRoleAuditWrite:              "vctl-audit-writer",
		DBRoleAuditIngest:             "vctl-audit-ingest",
		DBRoleAuditPrune:              "vctl-pruner",
		DBRoleOpenStackPrune:          "vctl-openstack-pruner",
		DBRoleReconcile:               "vctl-reconcile",
		DBRoleStatus:                  "vctl-status",
		DBRoleMigrate:                 "vctl-migrator",
		DBMigrationOwner:              "vctl_owner",
		KernelRetentionDays:           14,
		SessionRetentionDays:          365,
		AccessRetentionDays:           1095,
		OpenStackMissingRetentionDays: 180,
		CacheRefresh:                  "1h",
		CacheOfflineTTL:               "24h",
		// 7d. Was 720h (30d), chosen "long enough never to bite in practice" — which
		// is another way of saying the guard was off. Inventory drifts faster than a
		// month: a host in this fleet lost its primary address outright and the
		// database still carried the dead one days later. The snapshot refreshes
		// hourly, so a week-old one already means the database has been unreachable
		// for a week — at that point refusing to route is the safer answer.
		CacheMaxAge:          "168h",
		CARole:               "sre-core",
		SSHSign:              "30m",
		SSHDirectFirst:       true,
		SSHDefaultUser:       "ubuntu",
		SyncProbeTimeout:     "3s",
		SyncProbeConcurrency: 32,
		DCRules:              syncx.DefaultDCRules(),
		AppRoleMount:         "approle",
		KubernetesMount:      "kubernetes",
		AppRoleSelfRole:      "vctl-user",
		MOTDHeader:           sreMOTDHeader,
		MOTDManagedBy:        "Managed by Innogrid SRE Team.",
		MOTDColor:            true,
	}
}

// The masthead node-agent puts above the rendered farm topology (--motd).
// Figlet "INNOGRID" in ANSI Shadow: solid glyph bodies, so the banner colour
// fills the letters instead of tracing an outline. 60 columns — the full
// "Innogrid SRE" would be 88 and clip an 80-column terminal, so SRE sits as
// the signature line under the block.
const sreMOTDHeader = `██╗███╗   ██╗███╗   ██╗ ██████╗  ██████╗ ██████╗ ██╗██████╗
██║████╗  ██║████╗  ██║██╔═══██╗██╔════╝ ██╔══██╗██║██╔══██╗
██║██╔██╗ ██║██╔██╗ ██║██║   ██║██║  ███╗██████╔╝██║██║  ██║
██║██║╚██╗██║██║╚██╗██║██║   ██║██║   ██║██╔══██╗██║██║  ██║
██║██║ ╚████║██║ ╚████║╚██████╔╝╚██████╔╝██║  ██║██║██████╔╝
╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝╚═════╝
                                             ─────  S R E  ─`
