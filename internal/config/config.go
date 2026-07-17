// Package config loads and validates the agent bootstrap configuration.
package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	Agent   AgentConfig   `mapstructure:"agent"`
	Server  ServerConfig  `mapstructure:"server"`
	Runtime RuntimeConfig `mapstructure:"runtime"`
	Certs   CertsConfig   `mapstructure:"certs"`
}

type AgentConfig struct {
	ID               string            `mapstructure:"id"`
	Region           string            `mapstructure:"region"`
	Tags             map[string]string `mapstructure:"tags"`
	HostnameOverride string            `mapstructure:"hostname_override"`
}

type ServerConfig struct {
	EnrollURL         string        `mapstructure:"enroll_url"`
	ReportURL         string        `mapstructure:"report_url"`
	ProvisioningToken string        `mapstructure:"provisioning_token"`
	InsecureEnroll    bool          `mapstructure:"insecure_enroll"`
	TaskPollInterval  time.Duration `mapstructure:"task_poll_interval"`
	FlushInterval     time.Duration `mapstructure:"flush_interval"`
	BatchSize         int           `mapstructure:"batch_size"`
	RequestTimeout    time.Duration `mapstructure:"request_timeout"`
}

type LogConfig struct {
	File       string `mapstructure:"file"`
	Level      string `mapstructure:"level"` // debug / info / warn / error
	MaxSizeMB  int    `mapstructure:"max_size_mb"`
	MaxAgeDays int    `mapstructure:"max_age_days"`
	MaxBackups int    `mapstructure:"max_backups"`
	Compress   bool   `mapstructure:"compress"`
}

type RuntimeConfig struct {
	Log            LogConfig     `mapstructure:"log"`
	GracePeriod    time.Duration `mapstructure:"grace_period"`
	MaxConcurrency int           `mapstructure:"max_concurrency"`
}

type CertsConfig struct {
	Dir string `mapstructure:"dir"`
}

func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	v := viper.New()
	v.SetConfigType("yaml")
	if err := v.ReadConfig(strings.NewReader(os.ExpandEnv(string(raw)))); err != nil {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}

	v.SetDefault("server.task_poll_interval", "30s")
	v.SetDefault("server.flush_interval", "30s")
	v.SetDefault("server.batch_size", 100)
	v.SetDefault("server.request_timeout", "30s")
	v.SetDefault("runtime.grace_period", "30s")
	v.SetDefault("runtime.max_concurrency", 20)
	v.SetDefault("runtime.log.level", "info")
	v.SetDefault("runtime.log.max_size_mb", 100)
	v.SetDefault("runtime.log.max_age_days", 30)
	v.SetDefault("runtime.log.max_backups", 30)
	v.SetDefault("certs.dir", ".certs")

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}

	return &cfg, cfg.validate()
}

func (c *Config) validate() error {
	if c.Server.ReportURL == "" {
		return fmt.Errorf("server.report_url must not be empty")
	}
	if c.Runtime.MaxConcurrency <= 0 {
		return fmt.Errorf("runtime.max_concurrency must be positive")
	}
	return nil
}
