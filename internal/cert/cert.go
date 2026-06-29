// Package cert handles the agent certificate lifecycle: enrollment via provisioning
// token, persisting the issued mTLS credentials, constructing a mTLS http.Client,
// and renewing the certificate before it expires.
package cert

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	fileCACert  = "ca.crt"
	fileCert    = "client.crt"
	fileKey     = "client.key"
	fileAgentID = "agent_id"
)

type enrollRequest struct {
	Token    string `json:"provisioning_token"`
	Hostname string `json:"hostname"`
}

type enrollResponse struct {
	AgentID    string    `json:"agent_id"`
	CertPEM    string    `json:"cert_pem"`
	KeyPEM     string    `json:"key_pem"`
	CACertPEM  string    `json:"ca_cert_pem"`
	CertExpiry time.Time `json:"cert_expiry"`
	SyncPort   int       `json:"sync_port"`
}

type renewResponse struct {
	AgentID   string `json:"agent_id"`
	CertPEM   string `json:"cert_pem"`
	KeyPEM    string `json:"key_pem"`
	CACertPEM string `json:"ca_cert_pem"`
}

// HasCerts returns true only if all four credential files are present in dir.
func HasCerts(dir string) bool {
	for _, name := range []string{fileCACert, fileCert, fileKey, fileAgentID} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			return false
		}
	}
	return true
}

// Enroll registers this agent with the NMS server via a one-time provisioning token.
// On success it writes the four credential files into dir and returns the assigned AgentID.
// insecure allows skipping TLS verification of the enroll endpoint (useful when the server
// uses a self-signed cert that the agent doesn't yet trust).
func Enroll(enrollURL, token, hostname, dir string, insecure bool) (string, error) {
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure}, //nolint:gosec
		},
	}

	body, _ := json.Marshal(enrollRequest{Token: token, Hostname: hostname})
	resp, err := client.Post(
		strings.TrimRight(enrollURL, "/")+"/api/v1/agents/enroll",
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		return "", fmt.Errorf("enroll POST: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("enroll: server returned HTTP %d", resp.StatusCode)
	}

	var er enrollResponse
	if err := json.NewDecoder(resp.Body).Decode(&er); err != nil {
		return "", fmt.Errorf("decode enroll response: %w", err)
	}
	if er.AgentID == "" || er.CertPEM == "" || er.KeyPEM == "" || er.CACertPEM == "" {
		return "", fmt.Errorf("enroll: incomplete response from server")
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create cert dir %s: %w", dir, err)
	}

	writes := []struct {
		name    string
		content string
		perm    os.FileMode
	}{
		{fileCACert, er.CACertPEM, 0o644},
		{fileCert, er.CertPEM, 0o644},
		{fileKey, er.KeyPEM, 0o600},
		{fileAgentID, er.AgentID + "\n", 0o644},
	}
	for _, w := range writes {
		if err := os.WriteFile(filepath.Join(dir, w.name), []byte(w.content), w.perm); err != nil {
			return "", fmt.Errorf("write %s: %w", w.name, err)
		}
	}

	return er.AgentID, nil
}

// LoadAgentID reads the persisted agent ID from the cert directory.
func LoadAgentID(dir string) (string, error) {
	b, err := os.ReadFile(filepath.Join(dir, fileAgentID))
	if err != nil {
		return "", fmt.Errorf("read agent_id: %w", err)
	}
	id := strings.TrimSpace(string(b))
	if id == "" {
		return "", fmt.Errorf("agent_id file is empty")
	}
	return id, nil
}

// CertExpiry parses the client certificate PEM in dir and returns its NotAfter time.
func CertExpiry(dir string) (time.Time, error) {
	b, err := os.ReadFile(filepath.Join(dir, fileCert))
	if err != nil {
		return time.Time{}, fmt.Errorf("read cert: %w", err)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return time.Time{}, fmt.Errorf("no PEM block in %s", fileCert)
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse cert: %w", err)
	}
	return c.NotAfter, nil
}

// Renew calls POST /api/v1/agent-sync/renew-cert using the current mTLS client
// and overwrites the cert files on disk. Because NewMTLSClient uses DialTLSContext
// (reads certs from disk on every new TLS connection), subsequent connections
// automatically use the renewed certificate and CA without an agent restart.
func Renew(client *http.Client, syncURL, certDir string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(syncURL, "/")+"/api/v1/agent-sync/renew-cert", nil)
	if err != nil {
		return err
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("renew-cert POST: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("renew-cert: HTTP %d", resp.StatusCode)
	}

	var rr renewResponse
	if err := json.NewDecoder(resp.Body).Decode(&rr); err != nil {
		return fmt.Errorf("decode renew response: %w", err)
	}
	if rr.CertPEM == "" || rr.KeyPEM == "" {
		return fmt.Errorf("renew-cert: incomplete response (missing cert or key)")
	}

	writes := []struct {
		name    string
		content string
		perm    os.FileMode
	}{
		{fileCert, rr.CertPEM, 0o644},
		{fileKey, rr.KeyPEM, 0o600},
	}
	if rr.CACertPEM != "" {
		writes = append(writes, struct {
			name    string
			content string
			perm    os.FileMode
		}{fileCACert, rr.CACertPEM, 0o644})
	}
	for _, w := range writes {
		if err := os.WriteFile(filepath.Join(certDir, w.name), []byte(w.content), w.perm); err != nil {
			return fmt.Errorf("write %s: %w", w.name, err)
		}
	}
	return nil
}

// dialMTLS establishes a TLS connection for mTLS, reading the CA cert and client
// cert+key fresh from disk each call. This ensures CA rotation and cert renewal
// take effect on the next new connection without an agent restart.
func dialMTLS(ctx context.Context, network, addr, caFile, certFile, keyFile string) (net.Conn, error) {
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("parse CA cert: no valid PEM blocks")
	}

	clientCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load client cert/key: %w", err)
	}

	host, _, _ := net.SplitHostPort(addr)
	tlsDialer := &tls.Dialer{
		NetDialer: &net.Dialer{},
		Config: &tls.Config{
			Certificates: []tls.Certificate{clientCert},
			RootCAs:      pool,
			ServerName:   host,
			MinVersion:   tls.VersionTLS12,
		},
	}
	return tlsDialer.DialContext(ctx, network, addr)
}

// NewMTLSClient builds an http.Client that presents the agent's client certificate
// and trusts only the NMS server's CA. Both the CA cert and client cert are read
// from disk on every new TLS connection so that CA rotation and cert renewal take
// effect immediately without an agent restart.
func NewMTLSClient(dir string, timeout time.Duration) (*http.Client, error) {
	caFile := filepath.Join(dir, fileCACert)
	certFile := filepath.Join(dir, fileCert)
	keyFile := filepath.Join(dir, fileKey)

	// Validate files exist and are parseable at startup so errors surface immediately.
	if _, err := tls.LoadX509KeyPair(certFile, keyFile); err != nil {
		return nil, fmt.Errorf("load client cert/key: %w", err)
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}
	if !x509.NewCertPool().AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("parse CA cert: no valid PEM blocks")
	}

	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			// Re-read both certs from disk on every new TLS connection.
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialMTLS(ctx, network, addr, caFile, certFile, keyFile)
			},
		},
	}, nil
}

// NewMTLSClientForFamily is like NewMTLSClient but restricts all TCP connections
// to the given address family: "tcp4" for IPv4-only, "tcp6" for IPv6-only.
// Used to query the server's /my-ip reflection endpoint over each family
// separately, so the agent can discover its public addresses behind NAT.
func NewMTLSClientForFamily(dir string, timeout time.Duration, network string) (*http.Client, error) {
	caFile := filepath.Join(dir, fileCACert)
	certFile := filepath.Join(dir, fileCert)
	keyFile := filepath.Join(dir, fileKey)

	if _, err := tls.LoadX509KeyPair(certFile, keyFile); err != nil {
		return nil, fmt.Errorf("load client cert/key: %w", err)
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}
	if !x509.NewCertPool().AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("parse CA cert: no valid PEM blocks")
	}

	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialTLSContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
				// Force the specified network family (tcp4 or tcp6).
				return dialMTLS(ctx, network, addr, caFile, certFile, keyFile)
			},
		},
	}, nil
}
