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
	"time"

	"gopkg.in/yaml.v3"

	"github.com/ghdwlsgur/vctl/internal/syncx"
)

type Config struct {
	VaultAddr  string `yaml:"vault_addr"`
	AuthMethod string `yaml:"auth_method"` // userpass | oidc
	OIDCRole   string `yaml:"oidc_role"`   // Vault OIDC role (phase 2)
	OIDCMount  string `yaml:"oidc_mount"`  // Vault OIDC auth mount path

	DBHost           string `yaml:"db_host"`
	DBServerName     string `yaml:"db_server_name"` // TLS SNI override; defaults to DBHost. Use for port-forward/proxy where dial host != cert name.
	DBPort           int    `yaml:"db_port"`
	DBName           string `yaml:"db_name"`
	DBRoleRO         string `yaml:"db_role_ro"`         // database/creds/<ro> for read paths
	DBRoleRW         string `yaml:"db_role_rw"`         // database/creds/<rw> for sync/admin paths
	DBRoleStatus     string `yaml:"db_role_status"`     // database/creds/<status> for node-agent status updates
	DBRoleMigrate    string `yaml:"db_role_migrate"`    // database/creds/<migrator> for schema changes
	DBMigrationOwner string `yaml:"db_migration_owner"` // stable owner role for migration objects

	// Kernel-audit retention. Raw kernel_event rows are high-volume; sessions are
	// small metadata kept much longer as the dataset index. Pruning is delegated
	// to `vctl prune` (run by a CronJob), mirroring Teleport's storage-lifecycle model.
	KernelRetentionDays  int `yaml:"kernel_retention_days"`  // prune kernel_event older than this
	SessionRetentionDays int `yaml:"session_retention_days"` // prune audit_session older than this (0 = keep)

	CARole         string `yaml:"ca_role"`          // ssh/sign/<role>
	SSHSign        string `yaml:"ssh_sign"`         // issued cert TTL
	SSHDirectFirst bool   `yaml:"ssh_direct_first"` // try target directly before falling back to jump hosts

	SSHDefaultUser       string         `yaml:"ssh_default_user"`
	SyncProbeTimeout     string         `yaml:"sync_probe_timeout"`
	SyncProbeConcurrency int            `yaml:"sync_probe_concurrency"`
	DCRules              []syncx.DCRule `yaml:"dc_rules"`

	// AppRole supports non-interactive auto-auth for agent and exec re-auth.
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

	if err := os.MkdirAll(c.StateDir, 0o700); err != nil {
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

func (c *Config) applyEnv() {
	envStr(&c.VaultAddr, "VAULT_ADDR")
	envStr(&c.VaultAddr, "VGO_VAULT_ADDR")
	envStr(&c.VaultAddr, "VCTL_VAULT_ADDR")
	envStr(&c.AuthMethod, "VGO_AUTH_METHOD")
	envStr(&c.AuthMethod, "VCTL_AUTH_METHOD")
	envStr(&c.DBHost, "VGO_DB_HOST")
	envStr(&c.DBHost, "VCTL_DB_HOST")
	envStr(&c.DBServerName, "VCTL_DB_SERVERNAME")
	envInt(&c.DBPort, "VGO_DB_PORT")
	envInt(&c.DBPort, "VCTL_DB_PORT")
	envStr(&c.DBName, "VGO_DB_NAME")
	envStr(&c.DBName, "VCTL_DB_NAME")
	envStr(&c.DBRoleRO, "VGO_DB_ROLE_RO")
	envStr(&c.DBRoleRO, "VCTL_DB_ROLE_RO")
	envStr(&c.DBRoleRW, "VGO_DB_ROLE_RW")
	envStr(&c.DBRoleRW, "VCTL_DB_ROLE_RW")
	envStr(&c.DBRoleStatus, "VCTL_DB_ROLE_STATUS")
	envStr(&c.DBRoleMigrate, "VGO_DB_ROLE_MIGRATE")
	envStr(&c.DBRoleMigrate, "VCTL_DB_ROLE_MIGRATE")
	envStr(&c.DBMigrationOwner, "VGO_DB_MIGRATION_OWNER")
	envStr(&c.DBMigrationOwner, "VCTL_DB_MIGRATION_OWNER")
	envInt(&c.KernelRetentionDays, "VCTL_KERNEL_RETENTION_DAYS")
	envInt(&c.SessionRetentionDays, "VCTL_SESSION_RETENTION_DAYS")
	envStr(&c.CARole, "VGO_CA_ROLE")
	envStr(&c.CARole, "VCTL_CA_ROLE")
	envBool(&c.SSHDirectFirst, "VCTL_SSH_DIRECT_FIRST")
	envStr(&c.SSHDefaultUser, "VGO_SSH_DEFAULT_USER")
	envStr(&c.SSHDefaultUser, "VCTL_SSH_DEFAULT_USER")
	envStr(&c.SyncProbeTimeout, "VGO_SYNC_PROBE_TIMEOUT")
	envStr(&c.SyncProbeTimeout, "VCTL_SYNC_PROBE_TIMEOUT")
	envInt(&c.SyncProbeConcurrency, "VGO_SYNC_PROBE_CONCURRENCY")
	envInt(&c.SyncProbeConcurrency, "VCTL_SYNC_PROBE_CONCURRENCY")
	envStr(&c.AppRoleID, "VGO_ROLE_ID")
	envStr(&c.AppRoleID, "VCTL_ROLE_ID")
	envStr(&c.AppRoleSecretID, "VGO_SECRET_ID")
	envStr(&c.AppRoleSecretID, "VCTL_SECRET_ID")
	envStr(&c.AppRoleIDFile, "VGO_ROLE_ID_FILE")
	envStr(&c.AppRoleIDFile, "VCTL_ROLE_ID_FILE")
	envStr(&c.AppRoleSecretIDFile, "VGO_SECRET_ID_FILE")
	envStr(&c.AppRoleSecretIDFile, "VCTL_SECRET_ID_FILE")
	envStr(&c.AppRoleSelfRole, "VCTL_APPROLE_SELF_ROLE")
	envStr(&c.SinkPath, "VGO_SINK")
	envStr(&c.SinkPath, "VCTL_SINK")
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
