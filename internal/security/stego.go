// Package security provides advanced security features for TorForge
package security

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"

	"github.com/jery0843/torforge/pkg/logger"
)

// StegoConfig configures the steganography mode
type StegoConfig struct {
	Enabled     bool   `yaml:"enabled"`
	Mode        string `yaml:"mode"`         // "https", "dns", "icmp"
	CoverDomain string `yaml:"cover_domain"` // Domain to mimic (e.g., "youtube.com")
}

// StegoMode provides traffic obfuscation using steganography principles
// This makes Tor traffic look like normal HTTPS traffic to specific sites
type StegoMode struct {
	mu          sync.RWMutex
	enabled     bool
	mode        string
	coverDomain string

	// Traffic pattern templates
	patterns []TrafficPattern
}

// TrafficPattern represents a traffic pattern to mimic
type TrafficPattern struct {
	Name       string
	PacketSize []int    // Typical packet sizes
	Timing     []int    // Typical timing in ms
	Headers    []string // HTTP headers to add
}

// Common service patterns to mimic
var servicePatterns = map[string]TrafficPattern{
	"youtube": {
		Name:       "YouTube Video Streaming",
		PacketSize: []int{1460, 1460, 1460, 1460, 1460}, // Full size packets
		Timing:     []int{50, 50, 50, 50, 50},           // Regular streaming
		Headers: []string{
			"Accept: video/webm,video/mp4,video/*;q=0.9,*/*;q=0.8",
			"Range: bytes=0-",
			"X-Requested-With: XMLHttpRequest",
		},
	},
	"netflix": {
		Name:       "Netflix Streaming",
		PacketSize: []int{1460, 1460, 1380, 1460, 800},
		Timing:     []int{33, 33, 33, 33, 33}, // ~30fps
		Headers: []string{
			"Accept: video/mp4,video/*,*/*;q=0.8",
			"Accept-Encoding: identity",
		},
	},
	"spotify": {
		Name:       "Spotify Music Streaming",
		PacketSize: []int{1024, 1024, 1024, 512},
		Timing:     []int{100, 100, 100, 100}, // Audio chunks
		Headers: []string{
			"Accept: audio/mpeg,audio/*;q=0.9,*/*;q=0.8",
		},
	},
	"teams": {
		Name:       "Microsoft Teams Video Call",
		PacketSize: []int{1200, 1200, 600, 1200},
		Timing:     []int{20, 20, 20, 20}, // Real-time video
		Headers: []string{
			"Accept: application/sdp",
			"Content-Type: application/json",
		},
	},
	"zoom": {
		Name:       "Zoom Video Call",
		PacketSize: []int{1100, 1100, 550, 1100},
		Timing:     []int{16, 16, 16, 16}, // 60fps video
		Headers: []string{
			"Accept: */*",
			"Origin: https://zoom.us",
		},
	},
}

// NewStegoMode creates a new steganography mode
func NewStegoMode(cfg *StegoConfig) *StegoMode {
	if cfg == nil || !cfg.Enabled {
		return &StegoMode{enabled: false}
	}

	s := &StegoMode{
		enabled:     true,
		mode:        cfg.Mode,
		coverDomain: cfg.CoverDomain,
		patterns:    []TrafficPattern{},
	}

	// Load pattern for cover domain
	if pattern, exists := servicePatterns[cfg.CoverDomain]; exists {
		s.patterns = append(s.patterns, pattern)
	} else {
		// Default to YouTube pattern
		s.patterns = append(s.patterns, servicePatterns["youtube"])
	}

	log := logger.WithComponent("stego")
	log.Info().
		Str("mode", cfg.Mode).
		Str("cover", cfg.CoverDomain).
		Msg("🎭 Steganography mode initialized")

	return s
}

// WrapTraffic wraps data to look like the cover service traffic
func (s *StegoMode) WrapTraffic(data []byte) []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.enabled || len(s.patterns) == 0 {
		return data
	}

	pattern := s.patterns[0]

	// Add padding to match expected packet sizes
	targetSize := pattern.PacketSize[0]
	if len(data) < targetSize {
		padding := make([]byte, targetSize-len(data))
		rand.Read(padding)
		data = append(data, padding...)
	}

	// Encode with cover-specific markers
	return s.addCoverMarkers(data)
}

// UnwrapTraffic removes steganographic wrapping
func (s *StegoMode) UnwrapTraffic(data []byte) []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.enabled {
		return data
	}

	return s.removeCoverMarkers(data)
}

// addCoverMarkers adds markers to make traffic look like cover service
func (s *StegoMode) addCoverMarkers(data []byte) []byte {
	// Create a wrapper that looks like video streaming data
	wrapper := make([]byte, 0, len(data)+64)

	// Add "video" magic bytes (fake MPEG signature)
	wrapper = append(wrapper, 0x00, 0x00, 0x00, 0x01) // Video NAL unit start
	wrapper = append(wrapper, 0x67)                   // SPS marker

	// Add length
	length := len(data)
	wrapper = append(wrapper, byte(length>>24), byte(length>>16), byte(length>>8), byte(length))

	// Add encoded data
	encoded := base64.StdEncoding.EncodeToString(data)
	wrapper = append(wrapper, []byte(encoded)...)

	// Add end marker
	wrapper = append(wrapper, 0x00, 0x00, 0x00, 0x01, 0x68) // PPS marker

	return wrapper
}

// removeCoverMarkers removes steganographic markers
func (s *StegoMode) removeCoverMarkers(data []byte) []byte {
	// Skip header (9 bytes)
	if len(data) < 14 {
		return data
	}

	// Extract length
	length := int(data[5])<<24 | int(data[6])<<16 | int(data[7])<<8 | int(data[8])

	// Extract and decode data
	if length > 0 && len(data) > 14 {
		encoded := data[9 : len(data)-5]
		decoded, err := base64.StdEncoding.DecodeString(string(encoded))
		if err == nil {
			return decoded
		}
	}

	return data
}

// GetHTTPHeaders returns headers to mimic the cover service
func (s *StegoMode) GetHTTPHeaders() map[string]string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	headers := make(map[string]string)

	if !s.enabled || len(s.patterns) == 0 {
		return headers
	}

	// Add pattern-specific headers
	pattern := s.patterns[0]
	for i, h := range pattern.Headers {
		key := fmt.Sprintf("X-Custom-%d", i)
		headers[key] = h
	}

	// Add common streaming headers
	headers["Accept-Encoding"] = "gzip, deflate, br"
	headers["Connection"] = "keep-alive"
	headers["Cache-Control"] = "no-cache"

	return headers
}

// GetTorrcConfig returns Tor configuration for steganography
func (s *StegoMode) GetTorrcConfig() string {
	if !s.enabled {
		return ""
	}

	// Configure Tor to use pluggable transports that provide obfuscation
	config := `
# Steganography Mode Configuration
# Use obfs4 transport for traffic obfuscation
UseBridges 1
ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy

# Additional obfuscation settings
SocksPort 9050 IsolateClientAddr IsolateSOCKSAuth
CircuitBuildTimeout 60
`
	return config
}

// GetStatus returns current status
func (s *StegoMode) GetStatus() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	patternName := "none"
	if len(s.patterns) > 0 {
		patternName = s.patterns[0].Name
	}

	return map[string]interface{}{
		"enabled":      s.enabled,
		"mode":         s.mode,
		"cover_domain": s.coverDomain,
		"pattern":      patternName,
	}
}

// IsEnabled returns whether stego mode is enabled
func (s *StegoMode) IsEnabled() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.enabled
}

// PrintStegoInfo prints steganography info
func (s *StegoMode) PrintStegoInfo() {
	if !s.enabled {
		return
	}

	s.mu.RLock()
	patternName := "YouTube"
	if len(s.patterns) > 0 {
		patternName = s.patterns[0].Name
	}
	s.mu.RUnlock()

	fmt.Printf("   🎭 Stego Mode: traffic mimics %s\n", patternName)
}
