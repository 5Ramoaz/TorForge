package netfilter

import (
	"testing"

	"github.com/jery0843/torforge/pkg/config"
)

// TestNewTProxyManager tests creating a TProxy manager from user perspective
func TestNewTProxyManager(t *testing.T) {
	cfg := &config.TorConfig{
		TransPort: 9040,
	}

	mgr := NewTProxyManager(cfg)
	if mgr == nil {
		t.Fatal("NewTProxyManager() returned nil")
	}

	if mgr.cfg != cfg {
		t.Error("manager config not set correctly")
	}

	// Default values
	if mgr.markValue != 100 {
		t.Errorf("expected markValue 100, got %d", mgr.markValue)
	}

	if mgr.tableID != 100 {
		t.Errorf("expected tableID 100, got %d", mgr.tableID)
	}
}

// TestTProxyManagerIsActive tests checking active state
func TestTProxyManagerIsActive(t *testing.T) {
	cfg := &config.TorConfig{
		TransPort: 9040,
	}

	mgr := NewTProxyManager(cfg)

	// Initially not active
	if mgr.IsActive() {
		t.Error("manager should not be active initially")
	}
}

// TestTProxyManagerNotActiveByDefault tests that manager is not active by default
func TestTProxyManagerNotActiveByDefault(t *testing.T) {
	cfg := &config.TorConfig{
		TransPort: 9040,
	}

	mgr := NewTProxyManager(cfg)

	// Should be inactive before Apply is called
	if mgr.active {
		t.Error("manager should be inactive before Apply()")
	}
}

// TestTProxyRollbackIdempotent tests that rollback is idempotent
func TestTProxyRollbackIdempotent(t *testing.T) {
	cfg := &config.TorConfig{
		TransPort: 9040,
	}

	mgr := NewTProxyManager(cfg)

	// Rollback on inactive manager should not error
	if err := mgr.Rollback(); err != nil {
		t.Errorf("Rollback() on inactive manager error = %v", err)
	}

	// Multiple rollbacks should be safe
	if err := mgr.Rollback(); err != nil {
		t.Errorf("second Rollback() error = %v", err)
	}
}

// TestUDPProxyListenerInvalidAddress tests creating listener with invalid address
func TestUDPProxyListenerInvalidAddress(t *testing.T) {
	// Invalid address should fail
	_, err := NewUDPProxyListener("invalid:address:format", "127.0.0.1:9050")
	if err == nil {
		t.Error("expected error for invalid address")
	}
}

// TestUDPProxyListenerStart tests starting a UDP proxy listener
// Note: This test may fail without elevated privileges
func TestUDPProxyListenerStart(t *testing.T) {
	// Skip if running without elevated privileges (most common case)
	// UDP TProxy requires CAP_NET_ADMIN
	t.Skip("UDPProxyListener requires CAP_NET_ADMIN capability")
}

// TestSetSocketOption tests the socket option helper
func TestSetSocketOption(t *testing.T) {
	// This function uses python subprocess, so it may not work in all environments
	// Just verify it doesn't panic
	t.Run("no panic on invalid fd", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("setSocketOption panicked: %v", r)
			}
		}()
		// Invalid fd should just return error, not panic
		_ = setSocketOption(-1, 0, 19, 1)
	})
}
