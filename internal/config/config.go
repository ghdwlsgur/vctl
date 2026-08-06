// Package config holds vctl runtime configuration.
//
// Onboarding principle: new teammates should not need local setup.
// Defaults are compiled into the binary, and the private CA is embedded.
// Override values with repo-local .vctl/config.yaml, VCTL_*, or VAULT_ADDR.
package config

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/ghdwlsgur/vctl/internal/securefile"
	"github.com/ghdwlsgur/vctl/internal/syncx"
)

type Config struct {
	// OperatorNetworks are the address prefixes people actually reach things on.
	//
	// A machine here answers on several: a tenant network nobody outside the
	// farm can route to, a storage network, and one an operator can open in a
	// browser or ssh to. Nothing in the data says which is which — they are all
	// just addresses — so the listing would otherwise show whichever came first
	// and be right by accident.
	//
	// Org-specific, and overridable, because the answer is a fact about a
	// network rather than about OpenStack.
	OperatorNetworks []string `yaml:"operator_networks"`

	VaultAddr  string `yaml:"vault_addr"`
	AuthMethod string `yaml:"auth_method"` // userpass | oidc | approle | kubernetes
	OIDCRole   string `yaml:"oidc_role"`   // Vault OIDC role (phase 2)
	OIDCMount  string `yaml:"oidc_mount"`  // Vault OIDC auth mount path

	DBHost            string `yaml:"db_host"`
	DBServerName      string `yaml:"db_server_name"` // TLS SNI override; defaults to DBHost. Use for port-forward/proxy where dial host != cert name.
	DBPort            int    `yaml:"db_port"`
	DBName            string `yaml:"db_name"`
	DBRoleRO          string `yaml:"db_role_ro"`           // database/creds/<ro> for read paths
	DBRoleRW          string `yaml:"db_role_rw"`           // database/creds/<rw> for sync/admin paths
	DBRoleIdentity    string `yaml:"db_role_identity"`     // seen_users upsert during login
	DBRoleAuditRO     string `yaml:"db_role_audit_ro"`     // access/session/kernel audit reads
	DBRoleAuditWrite  string `yaml:"db_role_audit_write"`  // append-only SSH access records
	DBRoleAuditIngest string `yaml:"db_role_audit_ingest"` // host collector/session lifecycle
	DBRoleStatus      string `yaml:"db_role_status"`       // database/creds/<status> for node-agent status updates
	DBRoleMigrate     string `yaml:"db_role_migrate"`      // database/creds/<migrator> for schema changes
	DBMigrationOwner  string `yaml:"db_migration_owner"`   // stable owner role for migration objects
	LocalDBDSN        string `yaml:"-"`                    // dev/test only; env-only loopback DSN

	// Kernel-audit retention. Raw kernel_event rows are high-volume; sessions are
	// small metadata kept much longer as the dataset index. Deletion is delegated to
	// the prune CronJob, which runs SQL as the table owner and does not go through
	// vctl; `vctl retention` only reports against these horizons. Mirrors Teleport's
	// storage-lifecycle model.
	//
	// The kernel default is 14 days because that is what the volume holds, not
	// because 14 days is the ideal window. Measured in production: kernel_event
	// grows ~344 MB/day, so 90 days needs ~30 GB against a 20 GB PVC. That is not
	// a theoretical limit — the table filled the volume on 2026-07-19 and took
	// vctl-ro to 500s until the PVC was raised to 20 GB.
	//
	// It must also match the CronJob that actually enforces it (vctl-postgres
	// prune-cronjob.yaml, KERNEL_RETENTION_DAYS=14) — the CronJob's value is what
	// takes effect, and this one only decides what gets reported. While this said 90
	// and the job said 14, the report described a horizon nothing enforced. Raising it
	// here without raising the volume re-arms the outage.
	KernelRetentionDays  int `yaml:"kernel_retention_days"`  // kernel_event horizon reported/enforced
	SessionRetentionDays int `yaml:"session_retention_days"` // audit_session horizon (0 = keep forever)

	// Local inventory cache. A snapshot under StateDir keeps host lookup working
	// while Postgres is unreachable; see internal/invcache. Writes are unaffected
	// and still go only to Postgres.
	CacheDisabled   bool   `yaml:"cache_disabled"`    // never read or refresh the local snapshot
	CacheRefresh    string `yaml:"cache_refresh"`     // refresh the snapshot when it is older than this
	CacheOfflineTTL string `yaml:"cache_offline_ttl"` // how long cached RBAC grants may authorize an offline command
	CacheMaxAge     string `yaml:"cache_max_age"`     // refuse to serve a snapshot older than this (0 = no limit)

	CARole         string `yaml:"ca_role"`          // ssh/sign/<role>
	SSHSign        string `yaml:"ssh_sign"`         // issued cert TTL
	SSHDirectFirst bool   `yaml:"ssh_direct_first"` // try target directly before falling back to jump hosts

	SSHDefaultUser       string         `yaml:"ssh_default_user"`
	SyncProbeTimeout     string         `yaml:"sync_probe_timeout"`
	SyncProbeConcurrency int            `yaml:"sync_probe_concurrency"`
	DCRules              []syncx.DCRule `yaml:"dc_rules"`

	// AppRole supports non-interactive auto-auth for agent and exec re-auth.
	// Kubernetes auth, for vctl running as a pod. The ServiceAccount token is
	// projected by the kubelet, so there is no credential to configure — only
	// which Vault role to present it to.
	KubernetesMount     string `yaml:"kubernetes_mount"`
	KubernetesRole      string `yaml:"kubernetes_role"`
	KubernetesTokenFile string `yaml:"kubernetes_token_file"`

	AppRoleMount        string `yaml:"approle_mount"`
	AppRoleID           string `yaml:"role_id"`
	AppRoleSecretID     string `yaml:"secret_id"`
	AppRoleIDFile       string `yaml:"role_id_file"`
	AppRoleSecretIDFile string `yaml:"secret_id_file"`
	// AppRoleSelfRole is the approle that `vctl login` self-registers against:
	// after interactive auth it fetches role_id + a fresh secret_id and stores
	// them, so future runs auto-authenticate without prompting ("register the
	// agent on first login"). Requires the login token to permit secret-id gen.
	AppRoleSelfRole string `yaml:"approle_self_role"`

	// SinkPath is where agent mode writes a valid token for other tools.
	SinkPath string `yaml:"sink_path"`

	// Runtime-only fields.
	StateDir   string `yaml:"-"`
	ConfigPath string `yaml:"-"`
}

// Load merges defaults, repo-local config, and environment variables.
func Load() (*Config, error) {
	c := Defaults()
	if err := c.initRuntimePaths(); err != nil {
		return nil, err
	}

	if err := c.loadConfigFile(); err != nil {
		return nil, err
	}
	c.applyEnv()
	c.setDerivedDefaults()

	if err := securefile.EnsurePrivateDir(c.StateDir, 0o700); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Config) initRuntimePaths() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	c.StateDir = filepath.Join(home, ".vctl")
	c.ConfigPath = defaultConfigPath()
	return nil
}

func (c *Config) loadConfigFile() error {
	b, err := os.ReadFile(c.ConfigPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return yaml.Unmarshal(b, c)
}

// envStrPair / envIntPair apply VGO_<suffix> then VCTL_<suffix> (VCTL wins),
// the legacy→current precedence used for every dual-prefixed setting. Settings
// commented "VCTL-only" intentionally have no VGO_ alias.
func envStrPair(dst *string, suffix string) {
	envStr(dst, "VGO_"+suffix)
	envStr(dst, "VCTL_"+suffix)
}

func envIntPair(dst *int, suffix string) {
	envInt(dst, "VGO_"+suffix)
	envInt(dst, "VCTL_"+suffix)
}

func (c *Config) applyEnv() {
	envStr(&c.VaultAddr, "VAULT_ADDR") // standard Vault var (no prefix)
	envStrPair(&c.VaultAddr, "VAULT_ADDR")
	envStrPair(&c.AuthMethod, "AUTH_METHOD")
	envStrPair(&c.DBHost, "DB_HOST")
	envStr(&c.DBServerName, "VCTL_DB_SERVERNAME") // VCTL-only
	envIntPair(&c.DBPort, "DB_PORT")
	envStrPair(&c.DBName, "DB_NAME")
	envStrPair(&c.DBRoleRO, "DB_ROLE_RO")
	envStrPair(&c.DBRoleRW, "DB_ROLE_RW")
	envStr(&c.DBRoleIdentity, "VCTL_DB_ROLE_IDENTITY")
	envStr(&c.DBRoleAuditRO, "VCTL_DB_ROLE_AUDIT_RO")
	envStr(&c.DBRoleAuditWrite, "VCTL_DB_ROLE_AUDIT_WRITE")
	envStr(&c.DBRoleAuditIngest, "VCTL_DB_ROLE_AUDIT_INGEST")
	envStr(&c.DBRoleStatus, "VCTL_DB_ROLE_STATUS") // VCTL-only
	envStrPair(&c.DBRoleMigrate, "DB_ROLE_MIGRATE")
	envStrPair(&c.DBMigrationOwner, "DB_MIGRATION_OWNER")
	envStr(&c.LocalDBDSN, "VCTL_LOCAL_DB_DSN")
	envBool(&c.CacheDisabled, "VCTL_CACHE_DISABLE")                // VCTL-only
	envStr(&c.CacheRefresh, "VCTL_CACHE_REFRESH")                  // VCTL-only
	envStr(&c.CacheOfflineTTL, "VCTL_CACHE_OFFLINE_TTL")           // VCTL-only
	envStr(&c.CacheMaxAge, "VCTL_CACHE_MAX_AGE")                   // VCTL-only
	envInt(&c.KernelRetentionDays, "VCTL_KERNEL_RETENTION_DAYS")   // VCTL-only
	envInt(&c.SessionRetentionDays, "VCTL_SESSION_RETENTION_DAYS") // VCTL-only
	envStrPair(&c.CARole, "CA_ROLE")
	envBool(&c.SSHDirectFirst, "VCTL_SSH_DIRECT_FIRST") // VCTL-only
	envStrPair(&c.SSHDefaultUser, "SSH_DEFAULT_USER")
	envStrPair(&c.SyncProbeTimeout, "SYNC_PROBE_TIMEOUT")
	envIntPair(&c.SyncProbeConcurrency, "SYNC_PROBE_CONCURRENCY")
	envStrPair(&c.KubernetesMount, "KUBERNETES_MOUNT")
	envStrPair(&c.KubernetesRole, "KUBERNETES_ROLE")
	envStrPair(&c.KubernetesTokenFile, "KUBERNETES_TOKEN_FILE")
	envStrPair(&c.AppRoleID, "ROLE_ID")
	envStrPair(&c.AppRoleSecretID, "SECRET_ID")
	envStrPair(&c.AppRoleIDFile, "ROLE_ID_FILE")
	envStrPair(&c.AppRoleSecretIDFile, "SECRET_ID_FILE")
	envStr(&c.AppRoleSelfRole, "VCTL_APPROLE_SELF_ROLE") // VCTL-only
	envStrPair(&c.SinkPath, "SINK")
}

func (c *Config) setDerivedDefaults() {
	if c.SinkPath == "" {
		c.SinkPath = filepath.Join(c.StateDir, "token-sink")
	}
	if c.AppRoleIDFile == "" {
		c.AppRoleIDFile = filepath.Join(c.StateDir, "role-id")
	}
	if c.AppRoleSecretIDFile == "" {
		c.AppRoleSecretIDFile = filepath.Join(c.StateDir, "secret-id")
	}
}

func defaultConfigPath() string {
	if p := os.Getenv("VCTL_CONFIG"); p != "" {
		return p
	}
	if p := os.Getenv("VGO_CONFIG"); p != "" {
		return p
	}
	wd, err := os.Getwd()
	if err != nil {
		return "config.yaml"
	}
	return filepath.Join(wd, ".vctl", "config.yaml")
}

// CacheRefreshInterval is how stale the local inventory snapshot may get before
// an online command refreshes it.
//
// Measured against production rather than guessed: the inventory changed once
// in seven days, while a 5m interval rewrote all 122 hosts to disk up to 96
// times a workday. The query itself is free (0.25ms), but polling minute-wise
// for data that moves week-wise is the wrong shape, and it turns a one-row
// `vctl ssh <host>` into a full table scan.
//
// An hour still refreshes far more often than the data changes, and bounds the
// window in which another operator's change is invisible. Changes made *here*
// do not wait for it — the commands that write inventory refresh the snapshot
// directly.
func (c *Config) CacheRefreshInterval() time.Duration {
	return parseDurationOr(c.CacheRefresh, time.Hour)
}

// CacheOfflineWindow bounds how long cached command grants may authorize a
// command while Postgres is unreachable. Past it, offline mutate commands fail
// closed: a grant revoked during a long outage must not stay usable forever.
func (c *Config) CacheOfflineWindow() time.Duration {
	return parseDurationOr(c.CacheOfflineTTL, 24*time.Hour)
}

// CacheStaleLimit is the oldest inventory snapshot vctl will serve during an
// outage. Past it, host lookup fails rather than routing by topology that has
// had time to drift. An explicit "0" disables the limit.
//
// Seven days, not thirty. The snapshot refreshes hourly, so any age near this
// limit already means the database has been unreachable for that long — and
// addresses do move inside a week. Note this sits above CacheOfflineWindow (24h),
// so shortening it does not newly block anything that offline authorization would
// still have permitted; it only drops the long tail where vctl would route by a
// topology nobody had confirmed for weeks.
func (c *Config) CacheStaleLimit() time.Duration {
	if strings.TrimSpace(c.CacheMaxAge) == "0" {
		return 0
	}
	return parseDurationOr(c.CacheMaxAge, 7*24*time.Hour)
}

// parseDurationOr keeps a malformed or absent override from disabling a
// protective default — a bad VCTL_CACHE_OFFLINE_TTL should not widen the offline
// window, it should be ignored.
func parseDurationOr(s string, def time.Duration) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return def
	}
	return d
}

func (c *Config) SyncBuildOptions(prefix string) syncx.BuildOptions {
	timeout, err := time.ParseDuration(c.SyncProbeTimeout)
	if err != nil || timeout <= 0 {
		timeout = 3 * time.Second
	}
	return syncx.BuildOptions{
		Prefix:           prefix,
		DefaultUser:      c.SSHDefaultUser,
		CARole:           c.CARole,
		ProbeTimeout:     timeout,
		ProbeConcurrency: c.SyncProbeConcurrency,
		DCRules:          c.DCRules,
	}
}

func envStr(dst *string, key string) {
	if v := os.Getenv(key); v != "" {
		*dst = v
	}
}

func envInt(dst *int, key string) {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			*dst = n
		}
	}
}

func envBool(dst *bool, key string) {
	if v := os.Getenv(key); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			*dst = b
		}
	}
}
