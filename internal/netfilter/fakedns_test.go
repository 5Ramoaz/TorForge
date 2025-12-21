package netfilter

import (
	"net"
	"testing"
)

// TestNewFakeDNSServer tests creating a FakeDNS server from user perspective
func TestNewFakeDNSServer(t *testing.T) {
	cfg := &FakeDNSConfig{
		ListenAddr: "127.0.0.1:15353",
		FakeSubnet: "198.18.0.0/15",
		TTL:        60,
	}

	server, err := NewFakeDNSServer(cfg)
	if err != nil {
		t.Fatalf("NewFakeDNSServer() error = %v", err)
	}

	if server == nil {
		t.Fatal("NewFakeDNSServer() returned nil")
	}

	if server.ttl != 60 {
		t.Errorf("expected TTL 60, got %d", server.ttl)
	}

	if server.listenAddr != "127.0.0.1:15353" {
		t.Errorf("expected listen addr 127.0.0.1:15353, got %s", server.listenAddr)
	}
}

// TestFakeDNSInvalidSubnet tests that invalid subnet returns error
func TestFakeDNSInvalidSubnet(t *testing.T) {
	cfg := &FakeDNSConfig{
		ListenAddr: "127.0.0.1:15353",
		FakeSubnet: "invalid-subnet",
		TTL:        60,
	}

	_, err := NewFakeDNSServer(cfg)
	if err == nil {
		t.Error("expected error for invalid subnet")
	}
}

// TestFakeDNSGetFakeIP tests that user can get fake IPs for domains
func TestFakeDNSGetFakeIP(t *testing.T) {
	cfg := &FakeDNSConfig{
		ListenAddr: "127.0.0.1:15353",
		FakeSubnet: "198.18.0.0/15",
		TTL:        60,
	}

	server, err := NewFakeDNSServer(cfg)
	if err != nil {
		t.Fatalf("NewFakeDNSServer() error = %v", err)
	}

	// User queries for a domain
	ip1 := server.getFakeIP("example.com.")
	if ip1 == nil {
		t.Fatal("getFakeIP() returned nil")
	}

	// Same domain should return same IP (user expects consistency)
	ip2 := server.getFakeIP("example.com.")
	if !ip1.Equal(ip2) {
		t.Errorf("same domain should return same IP: %s vs %s", ip1, ip2)
	}

	// Different domain should get different IP
	ip3 := server.getFakeIP("google.com.")
	if ip1.Equal(ip3) {
		t.Error("different domains should get different IPs")
	}
}

// TestFakeDNSIsFakeIP tests user checking if IP is fake
func TestFakeDNSIsFakeIP(t *testing.T) {
	cfg := &FakeDNSConfig{
		ListenAddr: "127.0.0.1:15353",
		FakeSubnet: "198.18.0.0/15",
		TTL:        60,
	}

	server, err := NewFakeDNSServer(cfg)
	if err != nil {
		t.Fatalf("NewFakeDNSServer() error = %v", err)
	}

	tests := []struct {
		ip     string
		isFake bool
	}{
		{"198.18.0.1", true},     // Within fake subnet
		{"198.19.255.255", true}, // Edge of subnet
		{"8.8.8.8", false},       // Google DNS - not fake
		{"192.168.1.1", false},   // Private network - not fake
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			result := server.IsFakeIP(ip)
			if result != tt.isFake {
				t.Errorf("IsFakeIP(%s) = %v, want %v", tt.ip, result, tt.isFake)
			}
		})
	}
}

// TestFakeDNSGetDomainForIP tests reverse lookup from user perspective
func TestFakeDNSGetDomainForIP(t *testing.T) {
	cfg := &FakeDNSConfig{
		ListenAddr: "127.0.0.1:15353",
		FakeSubnet: "198.18.0.0/15",
		TTL:        60,
	}

	server, err := NewFakeDNSServer(cfg)
	if err != nil {
		t.Fatalf("NewFakeDNSServer() error = %v", err)
	}

	// User first queries a domain to create mapping
	domain := "test-domain.example.com."
	fakeIP := server.getFakeIP(domain)

	// User then looks up the domain for that IP
	foundDomain := server.GetDomainForIP(fakeIP)
	if foundDomain != domain {
		t.Errorf("GetDomainForIP() = %s, want %s", foundDomain, domain)
	}

	// Unknown IP should return empty string
	unknownIP := net.ParseIP("8.8.8.8")
	result := server.GetDomainForIP(unknownIP)
	if result != "" {
		t.Errorf("GetDomainForIP(unknown) = %s, want empty", result)
	}
}

// TestFakeDNSMappingCount tests user tracking number of mappings
func TestFakeDNSMappingCount(t *testing.T) {
	cfg := &FakeDNSConfig{
		ListenAddr: "127.0.0.1:15353",
		FakeSubnet: "198.18.0.0/15",
		TTL:        60,
	}

	server, err := NewFakeDNSServer(cfg)
	if err != nil {
		t.Fatalf("NewFakeDNSServer() error = %v", err)
	}

	// Initially no mappings
	if count := server.GetMappingCount(); count != 0 {
		t.Errorf("initial mapping count = %d, want 0", count)
	}

	// User creates mappings
	server.getFakeIP("domain1.com.")
	server.getFakeIP("domain2.com.")
	server.getFakeIP("domain3.com.")

	if count := server.GetMappingCount(); count != 3 {
		t.Errorf("mapping count = %d, want 3", count)
	}

	// Same domain doesn't increase count
	server.getFakeIP("domain1.com.")
	if count := server.GetMappingCount(); count != 3 {
		t.Errorf("mapping count after duplicate = %d, want 3", count)
	}
}

// TestFakeDNSStartStop tests server lifecycle from user perspective
func TestFakeDNSStartStop(t *testing.T) {
	cfg := &FakeDNSConfig{
		ListenAddr: "127.0.0.1:15354", // Different port to avoid conflicts
		FakeSubnet: "198.18.0.0/15",
		TTL:        60,
	}

	server, err := NewFakeDNSServer(cfg)
	if err != nil {
		t.Fatalf("NewFakeDNSServer() error = %v", err)
	}

	// Start should succeed
	if err := server.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Starting again should fail (user protection)
	if err := server.Start(); err == nil {
		t.Error("second Start() should return error")
	}

	// Stop should succeed
	if err := server.Stop(); err != nil {
		t.Errorf("Stop() error = %v", err)
	}

	// Stop is idempotent
	if err := server.Stop(); err != nil {
		t.Errorf("second Stop() error = %v", err)
	}
}

// TestPtrToIP tests PTR record conversion
func TestPtrToIP(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"1.0.18.198.in-addr.arpa.", "198.18.0.1"},
		{"255.255.19.198.in-addr.arpa.", "198.19.255.255"},
		{"invalid", ""},
		{"", ""},
		{"short.arpa.", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := ptrToIP(tt.input)
			if result != tt.expected {
				t.Errorf("ptrToIP(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

// TestIncrementIP tests IP address incrementing
func TestIncrementIP(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"198.18.0.0", "198.18.0.1"},
		{"198.18.0.255", "198.18.1.0"},
		{"198.18.255.255", "198.19.0.0"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			ip := net.ParseIP(tt.input).To4()
			incrementIP(ip)
			if ip.String() != tt.expected {
				t.Errorf("incrementIP(%s) = %s, want %s", tt.input, ip.String(), tt.expected)
			}
		})
	}
}
