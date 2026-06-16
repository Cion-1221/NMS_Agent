// Package config 负责加载与校验 config.yaml，是整个 Agent "纯配置驱动"
// 原则的唯一入口：业务代码只允许通过本包暴露的结构体读取参数，
// 不允许在功能模块中出现任何硬编码的 IP、周期、阈值等。
package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config 是 config.yaml 的根节点，字段顺序与 yaml 文件保持一致，便于对照阅读。
type Config struct {
	Agent   AgentConfig   `mapstructure:"agent"`
	Runtime RuntimeConfig `mapstructure:"runtime"`
	Server  ServerConfig  `mapstructure:"server"`
	Modules ModulesConfig `mapstructure:"modules"`
}

// AgentConfig 描述当前 Agent 在分布式拓扑中的身份。
type AgentConfig struct {
	ID               string            `mapstructure:"id"`
	Site             string            `mapstructure:"site"`
	Region           string            `mapstructure:"region"`
	Tags             map[string]string `mapstructure:"tags"`
	HostnameOverride string            `mapstructure:"hostname_override"`
}

// RuntimeConfig 是与具体业务无关的进程级运行参数。
type RuntimeConfig struct {
	LogLevel             string        `mapstructure:"log_level"`
	LogFormat            string        `mapstructure:"log_format"`
	LogOutput            string        `mapstructure:"log_output"`
	LogFilePath          string        `mapstructure:"log_file_path"`
	ShutdownGracePeriod  time.Duration `mapstructure:"shutdown_grace_period"`
	MaxModuleConcurrency int           `mapstructure:"max_module_concurrency"`
	PanicRecovery        bool          `mapstructure:"panic_recovery"`
}

// ServerConfig 描述如何把采集结果上报回中心 NMS Server。
type ServerConfig struct {
	ReportURL      string        `mapstructure:"report_url"`
	AuthToken      string        `mapstructure:"auth_token"`
	Protocol       string        `mapstructure:"protocol"`
	RequestTimeout time.Duration `mapstructure:"request_timeout"`
	BatchSize      int           `mapstructure:"batch_size"`
	FlushInterval  time.Duration `mapstructure:"flush_interval"`
	QueueCapacity  int           `mapstructure:"queue_capacity"`
	TLS            TLSConfig     `mapstructure:"tls"`
	Retry          RetryConfig   `mapstructure:"retry"`
}

type TLSConfig struct {
	InsecureSkipVerify bool   `mapstructure:"insecure_skip_verify"`
	CACertPath         string `mapstructure:"ca_cert_path"`
	ClientCertPath     string `mapstructure:"client_cert_path"`
	ClientKeyPath      string `mapstructure:"client_key_path"`
}

type RetryConfig struct {
	MaxRetries        int           `mapstructure:"max_retries"`
	InitialBackoff    time.Duration `mapstructure:"initial_backoff"`
	MaxBackoff        time.Duration `mapstructure:"max_backoff"`
	BackoffMultiplier float64       `mapstructure:"backoff_multiplier"`
}

// BaseModuleConfig 是绝大多数周期性模块共享的最小配置集合，
// 通过 mapstructure:",squash" 被各模块配置内联展开，避免重复定义。
type BaseModuleConfig struct {
	Enabled  bool          `mapstructure:"enabled"`
	Interval time.Duration `mapstructure:"interval"`
}

// NamedTarget 是"名字 + 地址"这种最常见探测目标的通用形态，
// 供 ping / tcp_ping / traceroute / mtr / mesh_ping 共用。
type NamedTarget struct {
	Name    string `mapstructure:"name"`
	Address string `mapstructure:"address"`
}

// ModulesConfig 汇总 15 个功能模块 + MeshPing 的全部配置。
type ModulesConfig struct {
	Ping               PingConfig               `mapstructure:"ping"`
	TCPPing            TCPPingConfig            `mapstructure:"tcp_ping"`
	HTTPCheck          HTTPCheckConfig          `mapstructure:"http_check"`
	DNSCheck           DNSCheckConfig           `mapstructure:"dns_check"`
	Traceroute         TracerouteConfig         `mapstructure:"traceroute"`
	MTR                MTRConfig                `mapstructure:"mtr"`
	Speedtest          SpeedtestConfig          `mapstructure:"speedtest"`
	MeshPing           MeshPingConfig           `mapstructure:"mesh_ping"`
	SNMPPoll           SNMPPollConfig           `mapstructure:"snmp_poll"`
	InterfaceDiscovery InterfaceDiscoveryConfig `mapstructure:"interface_discovery"`
	Netflow            NetflowConfig            `mapstructure:"netflow"`
	BGPCheck           BGPCheckConfig           `mapstructure:"bgp_check"`
	ConfigBackup       ConfigBackupConfig       `mapstructure:"config_backup"`
	ScriptEngine       ScriptEngineConfig       `mapstructure:"script_engine"`
	RemoteCommand      RemoteCommandConfig      `mapstructure:"remote_command"`
	Syslog             SyslogConfig             `mapstructure:"syslog"`
}

// ---------- 一、网络主动探测 ----------

type PingConfig struct {
	BaseModuleConfig `mapstructure:",squash"`
	Timeout          time.Duration `mapstructure:"timeout"`
	PacketCount      int           `mapstructure:"packet_count"`
	Privileged       bool          `mapstructure:"privileged"`
	Targets          []NamedTarget `mapstructure:"targets"`
}

type TCPPingConfig struct {
	BaseModuleConfig `mapstructure:",squash"`
	Timeout          time.Duration `mapstructure:"timeout"`
	Targets          []NamedTarget `mapstructure:"targets"`
}

type HTTPTarget struct {
	Name          string            `mapstructure:"name"`
	URL           string            `mapstructure:"url"`
	Method        string            `mapstructure:"method"`
	ExpectStatus  int               `mapstructure:"expect_status"`
	ExpectKeyword string            `mapstructure:"expect_keyword"`
	Headers       map[string]string `mapstructure:"headers"`
	SkipTLSVerify bool              `mapstructure:"skip_tls_verify"`
}

type HTTPCheckConfig struct {
	BaseModuleConfig `mapstructure:",squash"`
	Timeout          time.Duration `mapstructure:"timeout"`
	Targets          []HTTPTarget  `mapstructure:"targets"`
}

type DNSQuery struct {
	Domain         string `mapstructure:"domain"`
	RecordType     string `mapstructure:"record_type"`
	ExpectContains string `mapstructure:"expect_contains"`
}

type DNSCheckConfig struct {
	BaseModuleConfig `mapstructure:",squash"`
	Timeout          time.Duration `mapstructure:"timeout"`
	Resolver         string        `mapstructure:"resolver"`
	Queries          []DNSQuery    `mapstructure:"queries"`
}

type TracerouteConfig struct {
	BaseModuleConfig `mapstructure:",squash"`
	MaxHops          int           `mapstructure:"max_hops"`
	Timeout          time.Duration `mapstructure:"timeout"`
	ProbesPerHop     int           `mapstructure:"probes_per_hop"`
	Targets          []NamedTarget `mapstructure:"targets"`
}

type MTRConfig struct {
	BaseModuleConfig `mapstructure:",squash"`
	Cycles           int           `mapstructure:"cycles"`
	Timeout          time.Duration `mapstructure:"timeout"`
	MaxHops          int           `mapstructure:"max_hops"`
	Targets          []NamedTarget `mapstructure:"targets"`
}

type SpeedtestConfig struct {
	BaseModuleConfig `mapstructure:",squash"`
	ServerID         string `mapstructure:"server_id"`
	SaveHistory      bool   `mapstructure:"save_history"`
	HistoryPath      string `mapstructure:"history_path"`
}

// ---------- 二、Mesh 延迟矩阵 ----------

type MeshPingConfig struct {
	BaseModuleConfig `mapstructure:",squash"`
	Timeout          time.Duration `mapstructure:"timeout"`
	PacketCount      int           `mapstructure:"packet_count"`
	Privileged       bool          `mapstructure:"privileged"`
	Concurrency      int           `mapstructure:"concurrency"`
	SelfName         string        `mapstructure:"self_name"`
	Peers            []NamedTarget `mapstructure:"peers"`
}

// ---------- 三、网络设备监控 ----------

type SNMPv3Config struct {
	Username      string `mapstructure:"username"`
	SecurityLevel string `mapstructure:"security_level"`
	AuthProtocol  string `mapstructure:"auth_protocol"`
	AuthKey       string `mapstructure:"auth_key"`
	PrivProtocol  string `mapstructure:"priv_protocol"`
	PrivKey       string `mapstructure:"priv_key"`
}

// SNMPDevice 是不带 OID 列表的设备连接信息，供 interface_discovery 等
// "全量发现"类场景复用（这类场景的 OID 由代码内置的 IF-MIB 决定，无需配置）。
type SNMPDevice struct {
	Name      string        `mapstructure:"name"`
	Address   string        `mapstructure:"address"`
	Port      int           `mapstructure:"port"`
	Version   string        `mapstructure:"version"`
	Community string        `mapstructure:"community"`
	V3        *SNMPv3Config `mapstructure:"v3"`
}

type OIDItem struct {
	Name string `mapstructure:"name"`
	OID  string `mapstructure:"oid"`
}

type SNMPPollDevice struct {
	SNMPDevice `mapstructure:",squash"`
	OIDs       []OIDItem `mapstructure:"oids"`
}

type SNMPPollConfig struct {
	BaseModuleConfig `mapstructure:",squash"`
	Timeout          time.Duration    `mapstructure:"timeout"`
	Retries          int              `mapstructure:"retries"`
	Devices          []SNMPPollDevice `mapstructure:"devices"`
}

type InterfaceDiscoveryConfig struct {
	BaseModuleConfig `mapstructure:",squash"`
	Timeout          time.Duration `mapstructure:"timeout"`
	Devices          []SNMPDevice  `mapstructure:"devices"`
}

// NetflowConfig 没有 interval：receiver 模式下是常驻 UDP 监听（见 module.Emitter），
// forwarder 模式下同样是常驻转发循环，均不存在"周期性触发"的语义。
type NetflowConfig struct {
	Enabled        bool   `mapstructure:"enabled"`
	Mode           string `mapstructure:"mode"`
	ListenAddress  string `mapstructure:"listen_address"`
	Protocol       string `mapstructure:"protocol"`
	ForwardTo      string `mapstructure:"forward_to"`
	SampleRateHint int    `mapstructure:"sample_rate_hint"`
}

type BGPPeer struct {
	Name          string `mapstructure:"name"`
	DeviceAddress string `mapstructure:"device_address"`
	PeerIP        string `mapstructure:"peer_ip"`
	ExpectState   string `mapstructure:"expect_state"`
}

type BGPSNMPConfig struct {
	Community string `mapstructure:"community"`
	Version   string `mapstructure:"version"`
}

type BGPSSHConfig struct {
	Username       string `mapstructure:"username"`
	AuthMethod     string `mapstructure:"auth_method"`
	PrivateKeyPath string `mapstructure:"private_key_path"`
	Password       string `mapstructure:"password"`
	Vendor         string `mapstructure:"vendor"`
}

type BGPCheckConfig struct {
	BaseModuleConfig `mapstructure:",squash"`
	Method           string        `mapstructure:"method"`
	Peers            []BGPPeer     `mapstructure:"peers"`
	SNMP             BGPSNMPConfig `mapstructure:"snmp"`
	SSH              BGPSSHConfig  `mapstructure:"ssh"`
}

// ---------- 四、运维执行类 ----------

type BackupDevice struct {
	Name           string `mapstructure:"name"`
	Address        string `mapstructure:"address"`
	Port           int    `mapstructure:"port"`
	Username       string `mapstructure:"username"`
	AuthMethod     string `mapstructure:"auth_method"`
	PrivateKeyPath string `mapstructure:"private_key_path"`
	Password       string `mapstructure:"password"`
	Vendor         string `mapstructure:"vendor"`
	BackupCommand  string `mapstructure:"backup_command"`
}

type ConfigBackupConfig struct {
	BaseModuleConfig `mapstructure:",squash"`
	Timeout          time.Duration  `mapstructure:"timeout"`
	StoragePath      string         `mapstructure:"storage_path"`
	RetentionDays    int            `mapstructure:"retention_days"`
	Devices          []BackupDevice `mapstructure:"devices"`
}

type ScriptItem struct {
	Name        string        `mapstructure:"name"`
	Enabled     bool          `mapstructure:"enabled"`
	Interpreter string        `mapstructure:"interpreter"`
	Path        string        `mapstructure:"path"`
	Cron        string        `mapstructure:"cron"`
	Args        []string      `mapstructure:"args"`
	Timeout     time.Duration `mapstructure:"timeout"`
}

// ScriptEngineConfig 没有模块级 interval：它是常驻模块（实现 module.Emitter），
// 内部用 robfig/cron 按每个脚本自己的 cron 表达式触发执行，不存在统一周期。
type ScriptEngineConfig struct {
	Enabled             bool          `mapstructure:"enabled"`
	WorkDir             string        `mapstructure:"work_dir"`
	DefaultTimeout      time.Duration `mapstructure:"default_timeout"`
	AllowedInterpreters []string      `mapstructure:"allowed_interpreters"`
	Scripts             []ScriptItem  `mapstructure:"scripts"`
}

// RemoteCommandConfig 没有模块级 interval：节奏由 poll_interval 控制。
type RemoteCommandConfig struct {
	Enabled                bool          `mapstructure:"enabled"`
	ListenMode             string        `mapstructure:"listen_mode"`
	PollInterval           time.Duration `mapstructure:"poll_interval"`
	CommandSourceURL       string        `mapstructure:"command_source_url"`
	ResultCallbackURL      string        `mapstructure:"result_callback_url"`
	ExecutionTimeout       time.Duration `mapstructure:"execution_timeout"`
	MaxConcurrentCommands  int           `mapstructure:"max_concurrent_commands"`
	Whitelist              []string      `mapstructure:"whitelist"`
	Blacklist              []string      `mapstructure:"blacklist"`
	RequireConfirmationFor []string      `mapstructure:"require_confirmation_for"`
}

// ---------- 五、日志类 ----------

type SyslogLocalStorage struct {
	Enabled    bool   `mapstructure:"enabled"`
	Path       string `mapstructure:"path"`
	MaxSizeMB  int    `mapstructure:"max_size_mb"`
	MaxBackups int    `mapstructure:"max_backups"`
}

// SyslogConfig 没有模块级 interval：是常驻 UDP/TCP 监听（见 module.Emitter）。
type SyslogConfig struct {
	Enabled       bool               `mapstructure:"enabled"`
	ListenAddress string             `mapstructure:"listen_address"`
	Protocol      string             `mapstructure:"protocol"`
	ForwardTo     string             `mapstructure:"forward_to"`
	BufferSize    int                `mapstructure:"buffer_size"`
	ParseFormat   string             `mapstructure:"parse_format"`
	LocalStorage  SyslogLocalStorage `mapstructure:"local_storage"`
}

// Load 读取并解析指定路径的 config.yaml。
//
// 加载流程：
//  1. 读取原始文件内容；
//  2. 用 os.ExpandEnv 展开形如 "${NMS_AGENT_TOKEN}" 的占位符
//     （对应 yaml 中所有敏感字段，如鉴权 Token、SNMPv3 密钥、SSH 密码）；
//  3. 交给 viper 按 yaml 解析并 Unmarshal 进 Config 结构体
//     （viper 默认的 DecodeHook 已包含 StringToTimeDurationHookFunc，
//     因此 "30s" / "5m" 这类字符串会被自动转换为 time.Duration）；
//  4. 执行 Validate 做最基本的边界检查。
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read file %s: %w", path, err)
	}

	expanded := os.ExpandEnv(string(raw))

	v := viper.New()
	v.SetConfigType("yaml")
	if err := v.ReadConfig(strings.NewReader(expanded)); err != nil {
		return nil, fmt.Errorf("config: parse yaml: %w", err)
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("config: unmarshal: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config: validate: %w", err)
	}

	return &cfg, nil
}

// Validate 只检查"代码后续逻辑会无条件依赖、缺失即无法启动"的字段，
// 不在此重复 yaml schema 校验。
func (c *Config) Validate() error {
	if c.Agent.ID == "" {
		return fmt.Errorf("agent.id must not be empty")
	}
	if c.Agent.Site == "" {
		return fmt.Errorf("agent.site must not be empty")
	}
	if c.Server.ReportURL == "" {
		return fmt.Errorf("server.report_url must not be empty")
	}
	if c.Modules.MeshPing.Enabled && c.Modules.MeshPing.SelfName != c.Agent.Site {
		return fmt.Errorf("modules.mesh_ping.self_name (%q) must match agent.site (%q)",
			c.Modules.MeshPing.SelfName, c.Agent.Site)
	}
	if c.Runtime.MaxModuleConcurrency <= 0 {
		return fmt.Errorf("runtime.max_module_concurrency must be positive")
	}
	return nil
}
