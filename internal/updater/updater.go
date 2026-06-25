// Package updater downloads, verifies, and atomically applies a new agent binary,
// then replaces the running process so the new version takes effect immediately.
package updater

import (
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Update describes a pending agent update as returned by GET /api/v1/agent-sync/tasks.
type Update struct {
	Version  string `json:"version"`
	BinaryID uint   `json:"binary_id"`
	SHA256   string `json:"sha256"`
	FileSize int64  `json:"file_size"` // bytes; used to pre-allocate temp file
}

// Apply downloads the new binary from {syncURL}/api/v1/agent-sync/binary/{BinaryID}
// using the mTLS client, verifies its SHA-256, atomically replaces the running
// executable, then restarts the process.
// On Linux/Darwin the process is replaced in-place via syscall.Exec (same PID).
// On Windows the process exits cleanly and the service manager restarts it.
func Apply(client *http.Client, syncURL string, u Update) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate executable: %w", err)
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return fmt.Errorf("resolve symlink: %w", err)
	}

	downloadURL := strings.TrimRight(syncURL, "/") +
		fmt.Sprintf("/api/v1/agent-sync/binary/%d", u.BinaryID)

	tmp, sum, err := download(client, downloadURL, filepath.Dir(exe), u.FileSize)
	if err != nil {
		return err
	}

	want := strings.ToLower(strings.TrimSpace(u.SHA256))
	if sum != want {
		os.Remove(tmp)
		return fmt.Errorf("sha256 mismatch: got %s, want %s", sum, want)
	}

	if err := os.Chmod(tmp, 0o755); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("chmod: %w", err)
	}

	if err := os.Rename(tmp, exe); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("replace binary: %w", err)
	}

	return restart(exe)
}

// download fetches url into a temp file inside dir, computing SHA-256 on the fly.
// sizeHint is used to pre-allocate disk space when > 0 (best-effort).
// Returns the temp file path and its hex SHA-256 sum. Caller must remove on error.
func download(client *http.Client, url, dir string, sizeHint int64) (path, sha256sum string, err error) {
	// Binary downloads can be large; use a generous timeout regardless of the
	// client's default request_timeout.
	dl := *client
	dl.Timeout = 10 * time.Minute

	f, err := os.CreateTemp(dir, ".nms-agent-update-*")
	if err != nil {
		return "", "", fmt.Errorf("create temp file: %w", err)
	}
	path = f.Name()

	// Pre-allocate to avoid fragmentation on large binaries.
	if sizeHint > 0 {
		_ = f.Truncate(sizeHint)
		_, _ = f.Seek(0, io.SeekStart)
	}

	resp, err := dl.Get(url)
	if err != nil {
		f.Close()
		os.Remove(path)
		return "", "", fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		f.Close()
		os.Remove(path)
		return "", "", fmt.Errorf("download: HTTP %d", resp.StatusCode)
	}

	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(f, h), resp.Body); err != nil {
		f.Close()
		os.Remove(path)
		return "", "", fmt.Errorf("write: %w", err)
	}
	f.Close()
	return path, fmt.Sprintf("%x", h.Sum(nil)), nil
}
