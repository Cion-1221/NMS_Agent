// Package configbackup 通过 SSH 登录网络设备拉取配置并落盘备份
// （对应 config.yaml 的 modules.config_backup）。
//
// 推荐第三方库：golang.org/x/crypto/ssh（官方维护的 SSH 客户端实现）。
// 若目标设备需要拉取多个文件而不是一条命令的标准输出，可在同一个
// ssh.Client 连接上用 github.com/pkg/sftp 跑 SFTP 子系统替代 session.Output。
package configbackup

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Cion-1221/NMS_Agent/internal/config"
	"github.com/Cion-1221/NMS_Agent/internal/module"
)

const moduleName = "config_backup"

type BackupResult struct {
	Device    string `json:"device"`
	Address   string `json:"address"`
	FilePath  string `json:"file_path,omitempty"`
	SizeBytes int    `json:"size_bytes,omitempty"`
	Success   bool   `json:"success"`
	Error     string `json:"error,omitempty"`
}

type Module struct {
	cfg config.ConfigBackupConfig
	id  module.Identity
}

func New(cfg config.ConfigBackupConfig, id module.Identity) *Module {
	return &Module{cfg: cfg, id: id}
}

func (m *Module) Name() string { return moduleName }

func (m *Module) Run(ctx context.Context) ([]module.Result, error) {
	if len(m.cfg.Devices) == 0 {
		return nil, nil
	}

	if err := os.MkdirAll(m.cfg.StoragePath, 0o755); err != nil {
		return nil, fmt.Errorf("create storage_path %s: %w", m.cfg.StoragePath, err)
	}

	backups := make([]BackupResult, len(m.cfg.Devices))
	var wg sync.WaitGroup
	for i, dev := range m.cfg.Devices {
		i, dev := i, dev
		wg.Add(1)
		go func() {
			defer wg.Done()
			backups[i] = m.backup(ctx, dev)
		}()
	}
	wg.Wait()

	if m.cfg.RetentionDays > 0 {
		m.applyRetention()
	}

	results := make([]module.Result, len(backups))
	for i, b := range backups {
		results[i] = m.id.NewResult(moduleName, b)
	}
	return results, nil
}

func (m *Module) backup(ctx context.Context, dev config.BackupDevice) BackupResult {
	res := BackupResult{Device: dev.Name, Address: dev.Address}

	output, err := m.fetchConfig(ctx, dev)
	if err != nil {
		res.Error = err.Error()
		return res
	}

	filename := fmt.Sprintf("%s_%s.cfg", dev.Name, time.Now().UTC().Format("20060102T150405Z"))
	fullPath := filepath.Join(m.cfg.StoragePath, filename)

	if err := os.WriteFile(fullPath, output, 0o600); err != nil {
		res.Error = fmt.Sprintf("write file: %v", err)
		return res
	}

	res.Success = true
	res.FilePath = fullPath
	res.SizeBytes = len(output)
	return res
}

// fetchConfig 通过 SSH 登录设备并执行 backup_command，返回其标准输出。
// 用 net.Dialer.DialContext + ssh.NewClientConn（而不是更省事的 ssh.Dial）
// 是为了让 TCP 连接阶段也能响应 ctx 取消，配合 Agent 优雅停机。
func (m *Module) fetchConfig(ctx context.Context, dev config.BackupDevice) ([]byte, error) {
	authMethods, err := buildAuthMethods(dev)
	if err != nil {
		return nil, err
	}

	clientCfg := &ssh.ClientConfig{
		User:            dev.Username,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // TODO: 生产环境应替换为校验设备指纹的 FixedHostKey
		Timeout:         m.cfg.Timeout,
	}

	port := dev.Port
	if port == 0 {
		port = 22
	}
	addr := fmt.Sprintf("%s:%d", dev.Address, port)

	dialer := net.Dialer{Timeout: m.cfg.Timeout}
	rawConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(rawConn, addr, clientCfg)
	if err != nil {
		return nil, fmt.Errorf("ssh handshake: %w", err)
	}
	client := ssh.NewClient(sshConn, chans, reqs)
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("new session: %w", err)
	}
	defer session.Close()

	if dev.BackupCommand == "" {
		return nil, fmt.Errorf("backup_command must not be empty")
	}

	output, err := session.Output(dev.BackupCommand)
	if err != nil {
		return nil, fmt.Errorf("run %q: %w", dev.BackupCommand, err)
	}
	return output, nil
}

func buildAuthMethods(dev config.BackupDevice) ([]ssh.AuthMethod, error) {
	switch dev.AuthMethod {
	case "key":
		keyBytes, err := os.ReadFile(dev.PrivateKeyPath)
		if err != nil {
			return nil, fmt.Errorf("read private key: %w", err)
		}
		signer, err := ssh.ParsePrivateKey(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("parse private key: %w", err)
		}
		return []ssh.AuthMethod{ssh.PublicKeys(signer)}, nil

	case "password":
		if dev.Password == "" {
			return nil, fmt.Errorf("auth_method=password but password is empty")
		}
		return []ssh.AuthMethod{ssh.Password(dev.Password)}, nil

	default:
		return nil, fmt.Errorf("unsupported auth_method %q", dev.AuthMethod)
	}
}

// applyRetention 删除 storage_path 下修改时间超过 RetentionDays 的历史备份文件。
func (m *Module) applyRetention() {
	cutoff := time.Now().Add(-time.Duration(m.cfg.RetentionDays) * 24 * time.Hour)

	entries, err := os.ReadDir(m.cfg.StoragePath)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			_ = os.Remove(filepath.Join(m.cfg.StoragePath, e.Name()))
		}
	}
}
