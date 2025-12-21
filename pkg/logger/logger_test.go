package logger

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLoggerInit tests initializing the logger from user perspective
func TestLoggerInit(t *testing.T) {
	// Reset global logger state
	defer func() {
		Log = Log.Level(-1) // Reset
	}()

	cfg := Config{
		Level:   "info",
		Console: false,
	}

	if err := Init(cfg); err != nil {
		t.Fatalf("Init() error = %v", err)
	}
}

// TestLoggerInitWithFile tests file-based logging
func TestLoggerInitWithFile(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")

	cfg := Config{
		Level:   "debug",
		Console: false,
		File:    logFile,
	}

	if err := Init(cfg); err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	// Log something
	Info().Msg("test message")

	// Verify file was created
	if _, err := os.Stat(logFile); os.IsNotExist(err) {
		t.Error("log file was not created")
	}
}

// TestLoggerInitWithAudit tests audit log initialization
func TestLoggerInitWithAudit(t *testing.T) {
	tmpDir := t.TempDir()
	auditFile := filepath.Join(tmpDir, "audit.log")

	cfg := Config{
		Level:     "debug",
		Console:   false,
		AuditFile: auditFile,
	}

	if err := Init(cfg); err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	// Log an audit event
	Audit("test_event").Msg("test audit message")

	// Verify file was created
	if _, err := os.Stat(auditFile); os.IsNotExist(err) {
		t.Error("audit file was not created")
	}
}

// TestLoggerLevels tests logging at different levels
func TestLoggerLevels(t *testing.T) {
	cfg := Config{
		Level:   "debug",
		Console: false,
	}

	if err := Init(cfg); err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	// These should not panic
	Debug().Msg("debug message")
	Info().Msg("info message")
	Warn().Msg("warn message")
	Error().Msg("error message")
}

// TestLoggerWithComponent tests creating component-specific logger
func TestLoggerWithComponent(t *testing.T) {
	cfg := Config{
		Level:   "debug",
		Console: false,
	}

	if err := Init(cfg); err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	// User creates component-specific logger
	componentLog := WithComponent("test-component")

	// Should not panic
	componentLog.Info().Msg("component message")
}

// TestLoggerCircuitEvent tests logging circuit events
func TestLoggerCircuitEvent(t *testing.T) {
	cfg := Config{
		Level:   "debug",
		Console: false,
	}

	if err := Init(cfg); err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	// Should not panic
	CircuitEvent("circuit-123", "established")
}

// TestLoggerConnectionEvent tests logging connection events
func TestLoggerConnectionEvent(t *testing.T) {
	cfg := Config{
		Level:   "debug",
		Console: false,
	}

	if err := Init(cfg); err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	// Should not panic
	ConnectionEvent("192.168.1.1", "93.184.216.34", 443, "connected")
}

// TestLoggerSecurityEvent tests logging security events
func TestLoggerSecurityEvent(t *testing.T) {
	cfg := Config{
		Level:   "debug",
		Console: false,
	}

	if err := Init(cfg); err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	// Should not panic
	SecurityEvent("suspicious_activity", "multiple failed auth attempts")
}

// TestLoggerLeakEvent tests logging leak events
func TestLoggerLeakEvent(t *testing.T) {
	cfg := Config{
		Level:   "debug",
		Console: false,
	}

	if err := Init(cfg); err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	// Should not panic
	LeakEvent("dns_leak", "query to 8.8.8.8")
}

// TestLoggerLevelParsing tests different log levels
func TestLoggerLevelParsing(t *testing.T) {
	tests := []struct {
		level string
	}{
		{"debug"},
		{"info"},
		{"warn"},
		{"error"},
		{"invalid"}, // Should default to info
	}

	for _, tt := range tests {
		t.Run(tt.level, func(t *testing.T) {
			cfg := Config{
				Level:   tt.level,
				Console: false,
			}

			if err := Init(cfg); err != nil {
				t.Errorf("Init() with level %s error = %v", tt.level, err)
			}
		})
	}
}

// TestColorLevel tests the color formatting function
func TestColorLevel(t *testing.T) {
	tests := []struct {
		input    interface{}
		expected string
	}{
		{"debug", "\033[36mDBG\033[0m"},
		{"info", "\033[32mINF\033[0m"},
		{"warn", "\033[33mWRN\033[0m"},
		{"error", "\033[31mERR\033[0m"},
		{"fatal", "\033[35mFTL\033[0m"},
		{"panic", "\033[35mPNC\033[0m"},
		{"unknown", "unknown"},
		{123, "???"}, // Non-string input
	}

	for _, tt := range tests {
		name := "interface"
		if s, ok := tt.input.(string); ok {
			name = s
		}
		t.Run(name, func(t *testing.T) {
			result := colorLevel(tt.input)
			if result != tt.expected {
				t.Errorf("colorLevel(%v) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

// TestLoggerConsoleOutput tests console output mode
func TestLoggerConsoleOutput(t *testing.T) {
	cfg := Config{
		Level:   "debug",
		Console: true,
	}

	if err := Init(cfg); err != nil {
		t.Fatalf("Init() with console error = %v", err)
	}

	// Should not panic with console output
	Info().Msg("console test message")
}

// TestLoggerCreateDirectory tests auto-creation of log directory
func TestLoggerCreateDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	nestedLogFile := filepath.Join(tmpDir, "nested", "deep", "test.log")

	cfg := Config{
		Level:   "info",
		Console: false,
		File:    nestedLogFile,
	}

	if err := Init(cfg); err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	// Log something to trigger file creation
	Info().Msg("test")

	// Verify nested directory was created
	if _, err := os.Stat(filepath.Dir(nestedLogFile)); os.IsNotExist(err) {
		t.Error("nested log directory was not created")
	}
}
