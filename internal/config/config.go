// Package config holds vctl runtime configuration.
//
// 온보딩 원칙: 신규 팀원은 아무것도 설정하지 않는다.
// 모든 기본값은 바이너리에 baked-in 되어 있고(Defaults), 사설 CA 도 임베드된다.
// 필요하면 레포의 .vctl/config.yaml 또는 VCTL_* / VAULT_ADDR 환경변수로만 덮어쓴다.
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
	DBPort           int    `yaml:"db_port"`
	DBName           string `yaml:"db_name"`
	DBRoleRO         string `yaml:"db_role_ro"`         // database/creds/<ro>  읽기 (ssh/ls)
	DBRoleRW         string `yaml:"db_role_rw"`         // database/creds/<rw>  쓰기 (sync/admin)
	DBRoleMigrate    string `yaml:"db_role_migrate"`    // database/creds/<migrator> 스키마 변경
	DBMigrationOwner string `yaml:"db_migration_owner"` // 마이그레이션 객체의 stable owner role

	CARole  string `yaml:"ca_role"`  // ssh/sign/<role>
	SSHSign string `yaml:"ssh_sign"` // 발급 cert TTL

	SSHDefaultUser       string         `yaml:"ssh_default_user"`
	SyncProbeTimeout     string         `yaml:"sync_probe_timeout"`
	SyncProbeConcurrency int            `yaml:"sync_probe_concurrency"`
	DCRules              []syncx.DCRule `yaml:"dc_rules"`

	// AppRole — 무인 auto-auth (agent/exec 재인증). 값 또는 파일 경로로 지정.
	AppRoleMount        string `yaml:"approle_mount"`
	AppRoleID           string `yaml:"role_id"`
	AppRoleSecretID     string `yaml:"secret_id"`
	AppRoleIDFile       string `yaml:"role_id_file"`
	AppRoleSecretIDFile string `yaml:"secret_id_file"`

	// SinkPath — agent 모드가 유효 토큰을 떨궈두는 파일(다른 도구가 읽음).
	SinkPath string `yaml:"sink_path"`

	// 런타임 전용(직렬화 안 함)
	StateDir   string `yaml:"-"`
	ConfigPath string `yaml:"-"`
}

// Defaults 는 SRE 환경에 맞춘 컴파일 내장 기본값이다.
func Defaults() *Config {
	return &Config{
		VaultAddr:            "https://vault.sre.local",
		AuthMethod:           "userpass",
		OIDCRole:             "vctl",
		OIDCMount:            "oidc",
		DBHost:               "vctl-postgres.sre.local", // cert dnsName 과 일치(verify-full)
		DBPort:               5432,
		DBName:               "vctl",
		DBRoleRO:             "vctl-ro",
		DBRoleRW:             "vctl-rw",
		DBRoleMigrate:        "vctl-migrator",
		DBMigrationOwner:     "vctl_owner",
		CARole:               "sre-core",
		SSHSign:              "30m",
		SSHDefaultUser:       "ubuntu",
		SyncProbeTimeout:     "3s",
		SyncProbeConcurrency: 32,
		DCRules:              syncx.DefaultDCRules(),
		AppRoleMount:         "approle",
	}
}

// Load 는 기본값 → 레포 로컬 config.yaml → 환경변수 순으로 병합한다.
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
	envInt(&c.DBPort, "VGO_DB_PORT")
	envInt(&c.DBPort, "VCTL_DB_PORT")
	envStr(&c.DBName, "VGO_DB_NAME")
	envStr(&c.DBName, "VCTL_DB_NAME")
	envStr(&c.DBRoleRO, "VGO_DB_ROLE_RO")
	envStr(&c.DBRoleRO, "VCTL_DB_ROLE_RO")
	envStr(&c.DBRoleRW, "VGO_DB_ROLE_RW")
	envStr(&c.DBRoleRW, "VCTL_DB_ROLE_RW")
	envStr(&c.DBRoleMigrate, "VGO_DB_ROLE_MIGRATE")
	envStr(&c.DBRoleMigrate, "VCTL_DB_ROLE_MIGRATE")
	envStr(&c.DBMigrationOwner, "VGO_DB_MIGRATION_OWNER")
	envStr(&c.DBMigrationOwner, "VCTL_DB_MIGRATION_OWNER")
	envStr(&c.CARole, "VGO_CA_ROLE")
	envStr(&c.CARole, "VCTL_CA_ROLE")
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
	envStr(&c.SinkPath, "VGO_SINK")
	envStr(&c.SinkPath, "VCTL_SINK")
}

func (c *Config) setDerivedDefaults() {
	if c.SinkPath == "" {
		c.SinkPath = filepath.Join(c.StateDir, "token-sink")
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
