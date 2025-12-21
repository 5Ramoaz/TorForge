package bypass

import (
	"net"
	"testing"

	"github.com/jery0843/torforge/pkg/config"
)

func TestEngineMatchDomain(t *testing.T) {
	cfg := &config.BypassConfig{
		Enabled: true,
		Domains: []string{
			"*.local",
			"*.htb",
			"example.com",
		},
	}

	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	tests := []struct {
		domain  string
		matched bool
	}{
		{"test.local", true},
		{"sub.test.local", true},
		{"local", false}, // No wildcard match
		{"box.htb", true},
		{"hack.the.box.htb", true},
		{"example.com", true},
		{"sub.example.com", false}, // Exact match only
		{"google.com", false},
		{"notlocal.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			result := engine.MatchDomain(tt.domain)
			if result.Matched != tt.matched {
				t.Errorf("MatchDomain(%s) matched = %v, want %v", tt.domain, result.Matched, tt.matched)
			}
		})
	}
}

func TestEngineMatchIP(t *testing.T) {
	cfg := &config.BypassConfig{
		Enabled: true,
		CIDRs: []string{
			"10.0.0.0/8",
			"192.168.0.0/16",
			"172.16.0.0/12",
			"127.0.0.0/8",
		},
	}

	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	tests := []struct {
		ip      string
		matched bool
	}{
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"192.168.1.1", true},
		{"192.168.100.50", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"127.0.0.1", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"93.184.216.34", false}, // example.com
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			result := engine.MatchIP(ip)
			if result.Matched != tt.matched {
				t.Errorf("MatchIP(%s) matched = %v, want %v", tt.ip, result.Matched, tt.matched)
			}
		})
	}
}

func TestEngineMatchProtocol(t *testing.T) {
	cfg := &config.BypassConfig{
		Enabled:   true,
		Protocols: []string{"icmp", "ntp"},
	}

	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	tests := []struct {
		protocol string
		matched  bool
	}{
		{"icmp", true},
		{"ICMP", true}, // Case insensitive
		{"ntp", true},
		{"NTP", true},
		{"tcp", false},
		{"udp", false},
		{"http", false},
	}

	for _, tt := range tests {
		t.Run(tt.protocol, func(t *testing.T) {
			result := engine.MatchProtocol(tt.protocol)
			if result.Matched != tt.matched {
				t.Errorf("MatchProtocol(%s) matched = %v, want %v", tt.protocol, result.Matched, tt.matched)
			}
		})
	}
}

func TestEngineDisabled(t *testing.T) {
	cfg := &config.BypassConfig{
		Enabled: false,
		Domains: []string{"*.local"},
		CIDRs:   []string{"10.0.0.0/8"},
	}

	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	// Nothing should match when disabled
	if result := engine.MatchDomain("test.local"); result.Matched {
		t.Error("disabled engine should not match domain")
	}

	if result := engine.MatchIP(net.ParseIP("10.0.0.1")); result.Matched {
		t.Error("disabled engine should not match IP")
	}
}

func TestEngineAddRemoveRule(t *testing.T) {
	cfg := &config.BypassConfig{
		Enabled: true,
	}

	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	// Initially no match
	if result := engine.MatchDomain("test.example"); result.Matched {
		t.Error("should not match before adding rule")
	}

	// Add rule
	rule := Rule{
		Name:    "test-rule",
		Type:    RuleTypeDomain,
		Pattern: "*.example",
		Action:  ActionBypass,
	}
	if err := engine.AddRule(rule); err != nil {
		t.Fatalf("AddRule() error = %v", err)
	}

	// Now should match
	if result := engine.MatchDomain("test.example"); !result.Matched {
		t.Error("should match after adding rule")
	}

	// Remove rule
	if !engine.RemoveRule("test-rule") {
		t.Error("RemoveRule() returned false for existing rule")
	}

	// Should no longer match
	if result := engine.MatchDomain("test.example"); result.Matched {
		t.Error("should not match after removing rule")
	}

	// Removing non-existent rule
	if engine.RemoveRule("non-existent") {
		t.Error("RemoveRule() returned true for non-existent rule")
	}
}

func TestCompileGlobToRegex(t *testing.T) {
	tests := []struct {
		pattern string
		input   string
		match   bool
	}{
		{"*.local", "test.local", true},
		{"*.local", "sub.test.local", true},
		{"*.local", "local", false},
		{"test.*", "test.com", true},
		{"test.*", "test.anything", true},
		{"test.?", "test.a", true},
		{"test.?", "test.ab", false},
		{"exact.com", "exact.com", true},
		{"exact.com", "notexact.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"_"+tt.input, func(t *testing.T) {
			re, err := compileGlobToRegex(tt.pattern)
			if err != nil {
				t.Fatalf("compileGlobToRegex() error = %v", err)
			}

			matched := re.MatchString(tt.input)
			if matched != tt.match {
				t.Errorf("pattern %s on %s: got %v, want %v", tt.pattern, tt.input, matched, tt.match)
			}
		})
	}
}

func TestGetRules(t *testing.T) {
	cfg := &config.BypassConfig{
		Enabled: true,
	}

	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	// Add some rules
	rules := []Rule{
		{Name: "rule1", Type: RuleTypeDomain, Pattern: "*.test"},
		{Name: "rule2", Type: RuleTypeCIDR, Pattern: "10.0.0.0/8"},
	}

	for _, r := range rules {
		if err := engine.AddRule(r); err != nil {
			t.Fatalf("AddRule() error = %v", err)
		}
	}

	gotRules := engine.GetRules()
	if len(gotRules) != len(rules) {
		t.Errorf("GetRules() returned %d rules, want %d", len(gotRules), len(rules))
	}
}

func BenchmarkMatchDomain(b *testing.B) {
	cfg := &config.BypassConfig{
		Enabled: true,
		Domains: []string{
			"*.local",
			"*.htb",
			"*.thm",
			"*.internal",
			"*.corp",
		},
	}

	engine, _ := NewEngine(cfg)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.MatchDomain("test.htb")
	}
}

func BenchmarkMatchIP(b *testing.B) {
	cfg := &config.BypassConfig{
		Enabled: true,
		CIDRs: []string{
			"10.0.0.0/8",
			"172.16.0.0/12",
			"192.168.0.0/16",
			"100.64.0.0/10",
			"169.254.0.0/16",
		},
	}

	engine, _ := NewEngine(cfg)
	ip := net.ParseIP("192.168.1.100")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.MatchIP(ip)
	}
}
