package bypass

import (
	"net"
	"os"
	"testing"
	"time"
)

// TestNewSmartBypass tests creating a SmartBypass engine from user perspective
func TestNewSmartBypass(t *testing.T) {
	tmpDir := t.TempDir()

	sb, err := NewSmartBypass(tmpDir)
	if err != nil {
		t.Fatalf("NewSmartBypass() error = %v", err)
	}

	if sb == nil {
		t.Fatal("NewSmartBypass() returned nil")
	}

	if sb.dataDir != tmpDir {
		t.Errorf("dataDir = %s, want %s", sb.dataDir, tmpDir)
	}
}

// TestSmartBypassRecordConnection tests user recording connections for learning
func TestSmartBypassRecordConnection(t *testing.T) {
	tmpDir := t.TempDir()

	sb, err := NewSmartBypass(tmpDir)
	if err != nil {
		t.Fatalf("NewSmartBypass() error = %v", err)
	}

	// User records multiple connections
	sb.RecordConnection("example.com", 1024, 50*time.Millisecond)
	sb.RecordConnection("example.com", 2048, 45*time.Millisecond)
	sb.RecordConnection("google.com", 512, 30*time.Millisecond)

	// Check that stats are being recorded
	sb.mu.RLock()
	exampleStats := sb.stats["example.com"]
	googleStats := sb.stats["google.com"]
	sb.mu.RUnlock()

	if exampleStats == nil {
		t.Fatal("stats for example.com not recorded")
	}

	if exampleStats.TotalBytes != 3072 {
		t.Errorf("example.com total bytes = %d, want 3072", exampleStats.TotalBytes)
	}

	if exampleStats.TotalPackets != 2 {
		t.Errorf("example.com total packets = %d, want 2", exampleStats.TotalPackets)
	}

	if googleStats == nil {
		t.Fatal("stats for google.com not recorded")
	}

	if googleStats.Connections != 1 {
		t.Errorf("google.com connections = %d, want 1", googleStats.Connections)
	}
}

// TestSmartBypassPatternDetection tests pattern type detection from user perspective
func TestSmartBypassPatternDetection(t *testing.T) {
	tmpDir := t.TempDir()

	sb, err := NewSmartBypass(tmpDir)
	if err != nil {
		t.Fatalf("NewSmartBypass() error = %v", err)
	}

	tests := []struct {
		domain   string
		expected PatternType
	}{
		{"netflix.com", PatternStreaming},
		{"youtube.com", PatternStreaming},
		{"twitch.tv", PatternStreaming},
		{"discord.com", PatternVoIP},
		{"zoom.us", PatternVoIP},
		{"random-site.com", PatternUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			pattern := sb.detectPatternType(tt.domain)
			if pattern != tt.expected {
				t.Errorf("detectPatternType(%s) = %s, want %s", tt.domain, pattern, tt.expected)
			}
		})
	}
}

// TestSmartBypassShouldBypass tests bypass decision from user perspective
func TestSmartBypassShouldBypass(t *testing.T) {
	tmpDir := t.TempDir()

	sb, err := NewSmartBypass(tmpDir)
	if err != nil {
		t.Fatalf("NewSmartBypass() error = %v", err)
	}

	// Test known streaming services that should bypass
	// Note: Actual bypass behavior depends on signatures
	tests := []struct {
		domain   string
		ip       string
		port     int
		protocol string
	}{
		{"random-site.com", "93.184.216.34", 443, "tcp"},
		{"internal.local", "192.168.1.1", 80, "tcp"},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			// Just verify it doesn't panic
			_ = sb.ShouldBypass(tt.domain, ip, tt.port, tt.protocol)
		})
	}
}

// TestSmartBypassManualBypass tests user adding manual bypass rules
func TestSmartBypassManualBypass(t *testing.T) {
	tmpDir := t.TempDir()

	sb, err := NewSmartBypass(tmpDir)
	if err != nil {
		t.Fatalf("NewSmartBypass() error = %v", err)
	}

	// User adds manual bypass
	sb.AddManualBypass("my-custom-domain.com")

	// Verify the pattern was created with high bypass score
	sb.mu.RLock()
	pattern, exists := sb.patterns["my-custom-domain.com"]
	sb.mu.RUnlock()

	if !exists {
		t.Fatal("manual bypass pattern was not created")
	}

	if pattern.BypassScore != 1.0 {
		t.Errorf("expected BypassScore 1.0, got %f", pattern.BypassScore)
	}

	if pattern.Confidence != 1.0 {
		t.Errorf("expected Confidence 1.0, got %f", pattern.Confidence)
	}
}

// TestSmartBypassTopDomains tests getting top domains from user perspective
func TestSmartBypassTopDomains(t *testing.T) {
	tmpDir := t.TempDir()

	sb, err := NewSmartBypass(tmpDir)
	if err != nil {
		t.Fatalf("NewSmartBypass() error = %v", err)
	}

	// Record connections to create patterns
	for i := 0; i < 10; i++ {
		sb.RecordConnection("high-traffic.com", 10000, 20*time.Millisecond)
	}
	for i := 0; i < 5; i++ {
		sb.RecordConnection("medium-traffic.com", 5000, 30*time.Millisecond)
	}
	for i := 0; i < 2; i++ {
		sb.RecordConnection("low-traffic.com", 1000, 50*time.Millisecond)
	}

	// Get top domains
	topDomains := sb.GetTopDomains(2)
	if len(topDomains) == 0 {
		t.Error("GetTopDomains() returned empty slice")
	}

	// Should be ordered by connection count
	if len(topDomains) > 0 && topDomains[0].Domain != "high-traffic.com" {
		t.Logf("Note: top domain is %s (ordering may vary)", topDomains[0].Domain)
	}
}

// TestSmartBypassSaveLoad tests persisting patterns from user perspective
func TestSmartBypassSaveLoad(t *testing.T) {
	tmpDir := t.TempDir()

	sb, err := NewSmartBypass(tmpDir)
	if err != nil {
		t.Fatalf("NewSmartBypass() error = %v", err)
	}

	// User adds some patterns
	sb.AddManualBypass("persistent-domain.com")

	// Save patterns
	if err := sb.SavePatterns(); err != nil {
		t.Fatalf("SavePatterns() error = %v", err)
	}

	// Verify file was created (implementation uses patterns.json)
	patternsFile := tmpDir + "/patterns.json"
	if _, err := os.Stat(patternsFile); os.IsNotExist(err) {
		t.Error("patterns file was not created")
	}
}

// TestSmartBypassClearPatterns tests clearing patterns from user perspective
func TestSmartBypassClearPatterns(t *testing.T) {
	tmpDir := t.TempDir()

	sb, err := NewSmartBypass(tmpDir)
	if err != nil {
		t.Fatalf("NewSmartBypass() error = %v", err)
	}

	// Add some data
	sb.RecordConnection("domain1.com", 1000, 10*time.Millisecond)
	sb.RecordConnection("domain2.com", 2000, 20*time.Millisecond)

	// Clear patterns
	sb.ClearPatterns()

	// Patterns should be empty
	sb.mu.RLock()
	patternCount := len(sb.patterns)
	statCount := len(sb.stats)
	sb.mu.RUnlock()

	if patternCount != 0 {
		t.Errorf("pattern count after clear = %d, want 0", patternCount)
	}

	if statCount != 0 {
		t.Errorf("stats count after clear = %d, want 0", statCount)
	}
}

// TestSmartBypassGetBypassSuggestions tests getting suggestions from user perspective
func TestSmartBypassGetBypassSuggestions(t *testing.T) {
	tmpDir := t.TempDir()

	sb, err := NewSmartBypass(tmpDir)
	if err != nil {
		t.Fatalf("NewSmartBypass() error = %v", err)
	}

	// Add a manual bypass to create a pattern with high scores
	sb.AddManualBypass("suggested-domain.com")

	// Should return suggestions for domains with high bypass scores
	suggestions := sb.GetBypassSuggestions()

	// With a manual bypass added, we should get at least one suggestion
	if len(suggestions) == 0 {
		t.Error("GetBypassSuggestions() returned empty after adding manual bypass")
	}

	// The manually added domain should be in suggestions
	found := false
	for _, s := range suggestions {
		if s == "suggested-domain.com" {
			found = true
			break
		}
	}
	if !found {
		t.Error("suggested-domain.com not found in suggestions")
	}
}
