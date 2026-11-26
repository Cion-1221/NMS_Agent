package updater

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestDownloadAndChecksum(t *testing.T) {
	payload := []byte("fake-nms-agent-binary-v2.0.0")
	wantSum := fmt.Sprintf("%x", sha256.Sum256(payload))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	}))
	defer srv.Close()

	dir := t.TempDir()
	tmpPath, gotSum, err := download(srv.Client(), srv.URL, dir, int64(len(payload)))
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	defer os.Remove(tmpPath)

	if gotSum != wantSum {
		t.Fatalf("sha256 = %s, want %s", gotSum, wantSum)
	}
}

func TestReplaceBinaryUnixAndWindowsModes(t *testing.T) {
	for _, stageOld := range []bool{false, true} {
		dir := t.TempDir()
		exe := filepath.Join(dir, "nms-agent.exe")
		tmp := filepath.Join(dir, ".nms-agent-update-123")

		if err := os.WriteFile(exe, []byte("v1"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(tmp, []byte("v2"), 0o755); err != nil {
			t.Fatal(err)
		}

		if err := replaceBinary(tmp, exe, stageOld); err != nil {
			t.Fatalf("replaceBinary(stageOld=%v): %v", stageOld, err)
		}
		got, err := os.ReadFile(exe)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != "v2" {
			t.Fatalf("stageOld=%v: exe content = %q, want v2", stageOld, string(got))
		}
	}
}

func TestReplaceBinaryWindowsRollbackOnMissingTmp(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "nms-agent.exe")
	missingTmp := filepath.Join(dir, "does-not-exist")

	if err := os.WriteFile(exe, []byte("v1-intact"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := replaceBinary(missingTmp, exe, true); err == nil {
		t.Fatal("expected error when tmp binary is missing")
	}
	// Rollback must have restored the original executable at exe!
	got, err := os.ReadFile(exe)
	if err != nil {
		t.Fatalf("original exe missing after rollback: %v", err)
	}
	if string(got) != "v1-intact" {
		t.Fatalf("exe content after rollback = %q, want v1-intact", string(got))
	}
}
