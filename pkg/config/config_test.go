package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg == nil {
		t.Fatal("DefaultConfig returned nil")
	}

	// Test Tor defaults
	if cfg.Tor.Binary != "tor" {
		t.Errorf("expected tor binary 'tor', got '%s'", cfg.Tor.Binary)
	}
	if cfg.Tor.ControlPort != 9051 {
		t.Errorf("expected control port 9051, got %d", cfg.Tor.ControlPort)
	}
	if cfg.Tor.SOCKSPort != 9050 {
		t.Errorf("expected SOCKS port 9050, got %d", cfg.Tor.SOCKSPort)
	}
	if cfg.Tor.TransPort != 9040 {
		t.Errorf("expected trans port 9040, got %d", cfg.Tor.TransPort)
	}
	if cfg.Tor.DNSPort != 5353 {
		t.Errorf("expected DNS port 5353, got %d", cfg.Tor.DNSPort)
	}

	// Test Proxy defaults
	if !cfg.Proxy.Enabled {
		t.Error("expected proxy to be enabled by default")
	}
	if cfg.Proxy.Mode != "iptables" {
		t.Errorf("expected proxy mode 'iptables', got '%s'", cfg.Proxy.Mode)
	}

	// Test Circuit defaults
	if cfg.Circuits.MaxCircuits != 8 {
		t.Errorf("expected max circuits 8, got %d", cfg.Circuits.MaxCircuits)
	}
	if cfg.Circuits.RotationInterval != 10*time.Minute {
		t.Errorf("expected rotation interval 10m, got %v", cfg.Circuits.RotationInterval)
	}

	// Test Security defaults
	if !cfg.Security.KillSwitch {
		t.Error("expected kill switch to be enabled by default")
	}
	if !cfg.Security.DNSLeakProtection {
		t.Error("expected DNS leak protection to be enabled by default")
	}
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(*Config)
		wantErr bool
	}{
		{
			name:    "valid default config",
			modify:  func(c *Config) {},
			wantErr: false,
		},
		{
			name: "invalid control port (0)",
			modify: func(c *Config) {
				c.Tor.ControlPort = 0
			},
			wantErr: true,
		},
		{
			name: "invalid control port (too high)",
			modify: func(c *Config) {
				c.Tor.ControlPort = 70000
			},
			wantErr: true,
		},
		{
			name: "invalid SOCKS port",
			modify: func(c *Config) {
				c.Tor.SOCKSPort = -1
			},
			wantErr: true,
		},
		{
			name: "invalid trans port",
			modify: func(c *Config) {
				c.Tor.TransPort = 0
			},
			wantErr: true,
		},
		{
			name: "invalid max circuits",
			modify: func(c *Config) {
				c.Circuits.MaxCircuits = 0
			},
			wantErr: true,
		},
		{
			name: "invalid proxy mode",
			modify: func(c *Config) {
				c.Proxy.Mode = "invalid"
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			tt.modify(cfg)

			err := cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestLoadConfig(t *testing.T) {
	// Create temp config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test-config.yaml")

	configContent := `
tor:
  control_port: 9999
  socks_port: 9998
bypass:
  domains:
    - "*.test"
circuits:
  max_circuits: 8
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	// Verify loaded values
	if cfg.Tor.ControlPort != 9999 {
		t.Errorf("expected control port 9999, got %d", cfg.Tor.ControlPort)
	}
	if cfg.Tor.SOCKSPort != 9998 {
		t.Errorf("expected SOCKS port 9998, got %d", cfg.Tor.SOCKSPort)
	}
	if cfg.Circuits.MaxCircuits != 8 {
		t.Errorf("expected max circuits 8, got %d", cfg.Circuits.MaxCircuits)
	}
	if len(cfg.Bypass.Domains) != 1 || cfg.Bypass.Domains[0] != "*.test" {
		t.Errorf("expected bypass domain '*.test', got %v", cfg.Bypass.Domains)
	}
}

func TestLoadConfigInvalidPath(t *testing.T) {
	_, err := Load("/nonexistent/path/config.yaml")
	if err == nil {
		t.Error("expected error for nonexistent config file")
	}
}

func TestLoadConfigNoFile(t *testing.T) {
	// Should use defaults when no config file exists
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Tor.ControlPort != 9051 {
		t.Errorf("expected default control port 9051, got %d", cfg.Tor.ControlPort)
	}
}

func TestGetConfigDir(t *testing.T) {
	dir := GetConfigDir()
	if dir == "" {
		t.Error("GetConfigDir returned empty string")
	}
}

func TestGetDataDir(t *testing.T) {
	dir := GetDataDir()
	if dir == "" {
		t.Error("GetDataDir returned empty string")
	}
}
