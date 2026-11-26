// Package cert handles the agent certificate lifecycle: enrollment via provisioning
// token, persisting the issued mTLS credentials, constructing a mTLS http.Client,
// and renewing the certificate before it expires.
package cert

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	fileCACert  = "ca.crt"
	fileCert    = "client.crt"
	fileKey     = "client.key"
	fileAgentID = "agent_id"
)

type enrollRequest struct {
	Token    string            `json:"provisioning_token"`
	Hostname string            `json:"hostname"`
	Region   string            `json:"region,omitempty"`
	Tags     map[string]string `json:"tags,omitempty"`
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
func Enroll(enrollURL, token, hostname, region string, tags map[string]string, dir string, insecure bool) (string, error) {
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure}, //nolint:gosec
		},
	}
	defer client.CloseIdleConnections()

	body, _ := json.Marshal(enrollRequest{
		Token:    token,
		Hostname: hostname,
		Region:   region,
		Tags:     tags,
	})
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
	// Reject a mismatched pair before touching disk — the provisioning token
	// is consumed server-side, so bad credentials on disk are unrecoverable.
	if _, err := tls.X509KeyPair([]byte(er.CertPEM), []byte(er.KeyPEM)); err != nil {
		return "", fmt.Errorf("enroll: server returned mismatched cert/key: %w", err)
	}
	if _, err := normalizeCertBundlePEM([]byte(er.CACertPEM)); err != nil {
		return "", fmt.Errorf("enroll: invalid CA cert PEM: %w", err)
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create cert dir %s: %w", dir, err)
	}

	files := []credFile{
		{fileCACert, er.CACertPEM, 0o644},
		{fileCert, er.CertPEM, 0o644},
		{fileKey, er.KeyPEM, 0o600},
		{fileAgentID, er.AgentID + "\n", 0o644},
	}
	if err := writeCredFiles(dir, files); err != nil {
		return "", err
	}

	return er.AgentID, nil
}

// normalizeCertBundlePEM parses all CERTIFICATE blocks from raw PEM, validates each
// X.509 certificate, deduplicates by fingerprint, and returns canonical PEM bytes.
func normalizeCertBundlePEM(raw []byte) ([]byte, error) {
	var buf bytes.Buffer
	seen := make(map[string]bool, 4)
	count := 0
	rest := raw
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(c.Raw)
		fp := hex.EncodeToString(sum[:8])
		if seen[fp] {
			continue
		}
		seen[fp] = true
		count++
		_ = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes})
	}
	if count == 0 {
		return nil, fmt.Errorf("no valid CERTIFICATE PEM blocks")
	}
	return buf.Bytes(), nil
}

// CAFingerprints returns comma-joined sorted 16-hex SHA-256 prefixes of all CA
// certificates stored in dir/ca.crt (matches server core.CertFingerprint).
func CAFingerprints(dir string) string {
	raw, err := os.ReadFile(filepath.Join(dir, fileCACert))
	if err != nil {
		return ""
	}
	seen := make(map[string]bool, 4)
	var fps []string
	rest := raw
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		sum := sha256.Sum256(c.Raw)
		fp := hex.EncodeToString(sum[:8])
		if !seen[fp] {
			seen[fp] = true
			fps = append(fps, fp)
		}
	}
	sort.Strings(fps)
	return strings.Join(fps, ",")
}

// UpdateCABundle validates bundlePEM and atomically updates dir/ca.crt only when
// the normalized certificate set differs from what is already on disk.
func UpdateCABundle(dir, bundlePEM string) (bool, error) {
	nextNorm, err := normalizeCertBundlePEM([]byte(bundlePEM))
	if err != nil {
		return false, fmt.Errorf("validate CA bundle: %w", err)
	}
	if curRaw, err := os.ReadFile(filepath.Join(dir, fileCACert)); err == nil {
		if curNorm, err := normalizeCertBundlePEM(curRaw); err == nil && bytes.Equal(curNorm, nextNorm) {
			return false, nil
		}
	}
	if err := writeCredFiles(dir, []credFile{{fileCACert, string(nextNorm), 0o644}}); err != nil {
		return false, err
	}
	return true, nil
}

// credFile is one credential file to persist.
type credFile struct {
	name    string
	content string
	perm    os.FileMode
}

// writeCredFiles persists credential files near-atomically: every file is
// first staged as a temp file in dir, then all are renamed into place. A
// crash can no longer leave a half-written cert or key; the residual window
// for a mismatched cert/key pair shrinks from a full file write to the
// instant between two renames, and NewMTLSClient's startup validation
// catches that case explicitly.
func writeCredFiles(dir string, files []credFile) error {
	tmps := make([]string, len(files))
	cleanup := func() {
		for _, t := range tmps {
			if t != "" {
				os.Remove(t)
			}
		}
	}
	for i, f := range files {
		tmp, err := os.CreateTemp(dir, "."+f.name+".tmp-")
		if err != nil {
			cleanup()
			return fmt.Errorf("stage %s: %w", f.name, err)
		}
		tmps[i] = tmp.Name()
		_, werr := tmp.WriteString(f.content)
		if cerr := tmp.Close(); werr == nil {
			werr = cerr
		}
		if werr == nil {
			werr = os.Chmod(tmps[i], f.perm)
		}
		if werr != nil {
			cleanup()
			return fmt.Errorf("stage %s: %w", f.name, werr)
		}
	}
	for i, f := range files {
		if err := os.Rename(tmps[i], filepath.Join(dir, f.name)); err != nil {
			cleanup()
			return fmt.Errorf("write %s: %w", f.name, err)
		}
		tmps[i] = ""
	}
	return nil
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
// and overwrites the cert files on disk.
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
	// Never overwrite a working pair with a mismatched one.
	if _, err := tls.X509KeyPair([]byte(rr.CertPEM), []byte(rr.KeyPEM)); err != nil {
		return fmt.Errorf("renew-cert: server returned mismatched cert/key: %w", err)
	}

	files := []credFile{
		{fileCert, rr.CertPEM, 0o644},
		{fileKey, rr.KeyPEM, 0o600},
	}
	if rr.CACertPEM != "" {
		if normCA, err := normalizeCertBundlePEM([]byte(rr.CACertPEM)); err == nil {
			files = append(files, credFile{fileCACert, string(normCA), 0o644})
		}
	}
	return writeCredFiles(certDir, files)
}

// certReloader caches the parsed Root CA pool and client X.509 keypair in memory,
// re-parsing from disk only when file (ModTime, Size) metadata changes.
type certReloader struct {
	caFile   string
	certFile string
	keyFile  string

	mu       sync.RWMutex
	caMod    time.Time
	caSize   int64
	certMod  time.Time
	certSize int64
	keyMod   time.Time
	keySize  int64
	pool     *x509.CertPool
	pair     tls.Certificate
}

func newCertReloader(dir string) (*certReloader, error) {
	r := &certReloader{
		caFile:   filepath.Join(dir, fileCACert),
		certFile: filepath.Join(dir, fileCert),
		keyFile:  filepath.Join(dir, fileKey),
	}
	if _, _, err := r.load(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *certReloader) load() (*x509.CertPool, tls.Certificate, error) {
	caSt, err := os.Stat(r.caFile)
	if err != nil {
		return nil, tls.Certificate{}, fmt.Errorf("stat CA cert: %w", err)
	}
	certSt, err := os.Stat(r.certFile)
	if err != nil {
		return nil, tls.Certificate{}, fmt.Errorf("stat client cert: %w", err)
	}
	keySt, err := os.Stat(r.keyFile)
	if err != nil {
		return nil, tls.Certificate{}, fmt.Errorf("stat client key: %w", err)
	}

	r.mu.RLock()
	if r.pool != nil &&
		caSt.ModTime().Equal(r.caMod) && caSt.Size() == r.caSize &&
		certSt.ModTime().Equal(r.certMod) && certSt.Size() == r.certSize &&
		keySt.ModTime().Equal(r.keyMod) && keySt.Size() == r.keySize {
		pool, pair := r.pool, r.pair
		r.mu.RUnlock()
		return pool, pair, nil
	}
	r.mu.RUnlock()

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pool != nil &&
		caSt.ModTime().Equal(r.caMod) && caSt.Size() == r.caSize &&
		certSt.ModTime().Equal(r.certMod) && certSt.Size() == r.certSize &&
		keySt.ModTime().Equal(r.keyMod) && keySt.Size() == r.keySize {
		return r.pool, r.pair, nil
	}

	caPEM, err := os.ReadFile(r.caFile)
	if err != nil {
		return nil, tls.Certificate{}, fmt.Errorf("read CA cert: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, tls.Certificate{}, fmt.Errorf("parse CA cert: no valid PEM blocks")
	}
	pair, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return nil, tls.Certificate{}, fmt.Errorf("load client cert/key: %w", err)
	}

	r.caMod, r.caSize = caSt.ModTime(), caSt.Size()
	r.certMod, r.certSize = certSt.ModTime(), certSt.Size()
	r.keyMod, r.keySize = keySt.ModTime(), keySt.Size()
	r.pool = pool
	r.pair = pair
	return pool, pair, nil
}

func (r *certReloader) dialMTLS(ctx context.Context, network, addr string) (net.Conn, error) {
	pool, clientCert, err := r.load()
	if err != nil {
		return nil, err
	}
	host, _, splitErr := net.SplitHostPort(addr)
	if splitErr != nil {
		host = addr
	}
	tlsDialer := &tls.Dialer{
		NetDialer: &net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		},
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
// and trusts only the NMS server's CA bundle, automatically picking up on-disk
// CA rotations and certificate renewals without restarting the process.
func NewMTLSClient(dir string, timeout time.Duration) (*http.Client, error) {
	reloader, err := newCertReloader(dir)
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			MaxIdleConns:        16,
			MaxIdleConnsPerHost: 8,
			IdleConnTimeout:     90 * time.Second,
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return reloader.dialMTLS(ctx, network, addr)
			},
		},
	}, nil
}

// NewMTLSClientForFamily is like NewMTLSClient but restricts all TCP connections
// to the given address family: "tcp4" for IPv4-only, "tcp6" for IPv6-only.
func NewMTLSClientForFamily(dir string, timeout time.Duration, network string) (*http.Client, error) {
	reloader, err := newCertReloader(dir)
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			MaxIdleConns:        4,
			MaxIdleConnsPerHost: 2,
			IdleConnTimeout:     30 * time.Second,
			DialTLSContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
				return reloader.dialMTLS(ctx, network, addr)
			},
		},
	}, nil
}
