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
	"runtime"
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

// CleanupOldBinary removes any leftover "<exe>.old" left behind by a previous
// Windows in-place binary update. Safe to call unconditionally on startup.
func CleanupOldBinary() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	_ = os.Remove(exe + ".old")
}

// Apply downloads the new binary from {syncURL}/api/v1/agent-sync/binary/{BinaryID}
// using the mTLS client, verifies its SHA-256, replaces the running executable,
// then restarts the process.
// On Linux/Darwin the process is replaced in-place via syscall.Exec (same PID).
// On Windows the running image cannot be overwritten directly via MoveFileEx, so
// it is first renamed to "<exe>.old" before moving the new binary into place.
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

	if err := replaceBinary(tmp, exe, runtime.GOOS == "windows"); err != nil {
		return err
	}

	return restart(exe)
}

// replaceBinary swaps tmp into exe. When stageOld is true (Windows), the
// currently running binary at exe is renamed aside to exe+".old" first (Windows
// allows renaming a running image, whereas overwriting an existing running image
// fails with ERROR_ACCESS_DENIED), with automatic rollback if placing tmp fails.
func replaceBinary(tmp, exe string, stageOld bool) error {
	if !stageOld {
		if err := os.Rename(tmp, exe); err != nil {
			_ = os.Remove(tmp)
			return fmt.Errorf("replace binary: %w", err)
		}
		return nil
	}

	oldPath := exe + ".old"
	_ = os.Remove(oldPath)
	if err := os.Rename(exe, oldPath); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("move running binary aside: %w", err)
	}
	if err := os.Rename(tmp, exe); err != nil {
		_ = os.Rename(oldPath, exe)
		_ = os.Remove(tmp)
		return fmt.Errorf("replace binary: %w", err)
	}
	// Best-effort cleanup; on Windows the running image holds a lock until exit,
	// so CleanupOldBinary() removes it on the next process startup.
	_ = os.Remove(oldPath)
	return nil
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
		// The temp file MUST live next to the executable: os.Rename is only atomic
		// within one filesystem. A read-only install dir (typically systemd
		// ProtectSystem=strict without the install dir in ReadWritePaths) lands here.
		return "", "", fmt.Errorf("create temp file: %w (OTA writes the new binary next to the executable for an atomic rename — under systemd ProtectSystem=strict the install directory must be listed in ReadWritePaths)", err)
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
