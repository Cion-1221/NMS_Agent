package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadStrictBracedEnvExpansion(t *testing.T) {
	t.Setenv("NMS_TEST_TOKEN", "sec$ret$123")
	os.Unsetenv("NMS_UNSET_VAR")

	yamlContent := `# Comment with ${NMS_UNSET_VAR} and $SHOULD_BE_IGNORED
agent:
  region: "SIN"
  tags:
    env: "prod$1"
server:
  enroll_url: "https://nms.example.com:8443"
  report_url: "https://nms.example.com:8444"
  provisioning_token: "${NMS_TEST_TOKEN}"
runtime:
  max_concurrency: 15
`
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(yamlContent), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.ProvisioningToken != "sec$ret$123" {
		t.Fatalf("ProvisioningToken = %q, want %q", cfg.Server.ProvisioningToken, "sec$ret$123")
	}
	// Bare '$1' must NOT be stripped by os.ExpandEnv!
	if cfg.Agent.Tags["env"] != "prod$1" {
		t.Fatalf("bare '$' was mangled: got %q, want %q", cfg.Agent.Tags["env"], "prod$1")
	}
	if cfg.Runtime.MaxConcurrency != 15 {
		t.Fatalf("MaxConcurrency = %d, want 15", cfg.Runtime.MaxConcurrency)
	}
}

func TestLoadValidationRejectsEmptyReportURL(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(p, []byte("server:\n  report_url: \"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil {
		t.Fatal("expected error when server.report_url is empty")
	}
}
