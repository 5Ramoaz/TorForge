// Package ai provides AI-powered features for TorForge
package ai

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// AppCategory represents the sensitivity category of an application
type AppCategory int

const (
	CategoryUnknown     AppCategory = iota
	CategoryAlwaysTor               // Sensitive apps - always through Tor
	CategoryNeverTor                // Speed-critical - never through Tor
	CategoryLearning                // AI is still learning
	CategoryUserDefined             // Manually configured by user
)

func (c AppCategory) String() string {
	switch c {
	case CategoryAlwaysTor:
		return "always_tor"
	case CategoryNeverTor:
		return "direct"
	case CategoryLearning:
		return "learning"
	case CategoryUserDefined:
		return "user_defined"
	default:
		return "unknown"
	}
}

// AppProfile stores learned behavior for an application
type AppProfile struct {
	Name           string      `json:"name"`
	ExecutablePath string      `json:"executable_path"`
	Category       AppCategory `json:"category"`

	// Learning data
	ConnectionCount   int      `json:"connection_count"`
	SensitivePatterns int      `json:"sensitive_patterns"` // E.g., accessed .onion, banking sites
	SpeedSensitive    int      `json:"speed_sensitive"`    // E.g., streaming, large downloads
	Domains           []string `json:"domains"`            // Domains accessed

	// Confidence score (0-1)
	Confidence  float64   `json:"confidence"`
	LastUpdated time.Time `json:"last_updated"`
}

// SplitTunnelAI learns which apps need Tor vs direct connection
type SplitTunnelAI struct {
	mu sync.RWMutex

	// Learned app profiles
	appProfiles map[string]*AppProfile

	// Known patterns
	sensitivePatterns []*regexp.Regexp // Always route through Tor
	speedPatterns     []*regexp.Regexp // Prefer direct

	// Configuration
	dataDir             string
	learningEnabled     bool
	confidenceThreshold float64

	// Sensitive domains (always Tor)
	sensitiveDomains map[string]bool

	// Speed domains (prefer direct)
	speedDomains map[string]bool
}

// NewSplitTunnelAI creates a new split tunnel intelligence system
func NewSplitTunnelAI(dataDir string) *SplitTunnelAI {
	ai := &SplitTunnelAI{
		appProfiles:         make(map[string]*AppProfile),
		dataDir:             dataDir,
		learningEnabled:     true,
		confidenceThreshold: 0.7,
		sensitiveDomains:    make(map[string]bool),
		speedDomains:        make(map[string]bool),
	}

	// Initialize known patterns
	ai.initPatterns()

	// Load saved data
	ai.loadData()

	return ai
}

// initPatterns sets up known sensitive and speed patterns
func (ai *SplitTunnelAI) initPatterns() {
	// Sensitive patterns - ALWAYS through Tor
	sensitivePatternStrs := []string{
		`\.onion$`,                   // Onion sites
		`(bank|banking)\.`,           // Banking
		`(secure|login|auth)\.`,      // Authentication
		`(proton|tutanota)mail`,      // Secure email
		`(signal|telegram|whatsapp)`, // Messaging
		`(tor|tails|whonix)`,         // Privacy tools
		`(vpn|proxy)`,                // VPN/proxy services
		`(crypto|bitcoin|ethereum)`,  // Cryptocurrency
		`(health|medical|hospital)`,  // Medical
		`(legal|lawyer|attorney)`,    // Legal
	}

	for _, p := range sensitivePatternStrs {
		if re, err := regexp.Compile(p); err == nil {
			ai.sensitivePatterns = append(ai.sensitivePatterns, re)
		}
	}

	// Speed patterns - prefer direct
	speedPatternStrs := []string{
		`(youtube|netflix|hulu|disney)`,  // Streaming
		`(spotify|soundcloud|music)`,     // Music
		`(steam|epic|origin|gog)`,        // Gaming
		`(cdn|cloudfront|akamai|fastly)`, // CDNs
		`(update|download|patch)`,        // Updates
		`\.(mp4|mkv|avi|mov)$`,           // Video files
		`\.(iso|zip|tar|gz)$`,            // Large files
	}

	for _, p := range speedPatternStrs {
		if re, err := regexp.Compile(p); err == nil {
			ai.speedPatterns = append(ai.speedPatterns, re)
		}
	}

	// Known sensitive domains
	ai.sensitiveDomains = map[string]bool{
		"protonmail.com":  true,
		"tutanota.com":    true,
		"signal.org":      true,
		"duckduckgo.com":  true,
		"privacytools.io": true,
		"torproject.org":  true,
		"eff.org":         true,
	}

	// Known speed domains
	ai.speedDomains = map[string]bool{
		"youtube.com":      true,
		"googlevideo.com":  true,
		"netflix.com":      true,
		"nflxvideo.net":    true,
		"spotify.com":      true,
		"steampowered.com": true,
		"steamcontent.com": true,
		"akamaized.net":    true,
	}
}

// ShouldUseTor determines if an app/domain should use Tor
func (ai *SplitTunnelAI) ShouldUseTor(appName, domain string) (useTor bool, confidence float64, reason string) {
	ai.mu.RLock()
	defer ai.mu.RUnlock()

	// Check known sensitive domains first
	domainLower := strings.ToLower(domain)
	for d := range ai.sensitiveDomains {
		if strings.Contains(domainLower, d) {
			return true, 1.0, "sensitive_domain"
		}
	}

	// Check known speed domains
	for d := range ai.speedDomains {
		if strings.Contains(domainLower, d) {
			return false, 1.0, "speed_domain"
		}
	}

	// Check sensitive patterns
	for _, pattern := range ai.sensitivePatterns {
		if pattern.MatchString(domainLower) {
			return true, 0.9, "sensitive_pattern"
		}
	}

	// Check speed patterns
	for _, pattern := range ai.speedPatterns {
		if pattern.MatchString(domainLower) {
			return false, 0.9, "speed_pattern"
		}
	}

	// Check learned app profile
	if profile, exists := ai.appProfiles[appName]; exists {
		if profile.Category == CategoryUserDefined {
			return profile.Category == CategoryAlwaysTor, 1.0, "user_defined"
		}

		if profile.Confidence >= ai.confidenceThreshold {
			useTor = profile.Category == CategoryAlwaysTor
			return useTor, profile.Confidence, "learned"
		}
	}

	// Default: use Tor for safety
	return true, 0.5, "default_safe"
}

// RecordConnection records a connection for learning
func (ai *SplitTunnelAI) RecordConnection(appName, execPath, domain string, isSensitive, isSpeedCritical bool) {
	if !ai.learningEnabled {
		return
	}

	ai.mu.Lock()
	defer ai.mu.Unlock()

	// Get or create profile
	profile, exists := ai.appProfiles[appName]
	if !exists {
		profile = &AppProfile{
			Name:           appName,
			ExecutablePath: execPath,
			Category:       CategoryLearning,
			Domains:        []string{},
		}
		ai.appProfiles[appName] = profile
	}

	// Skip if user-defined
	if profile.Category == CategoryUserDefined {
		return
	}

	// Update stats
	profile.ConnectionCount++
	profile.LastUpdated = time.Now()

	// Track domain
	if !contains(profile.Domains, domain) && len(profile.Domains) < 100 {
		profile.Domains = append(profile.Domains, domain)
	}

	// Check patterns for this domain
	domainLower := strings.ToLower(domain)
	for _, pattern := range ai.sensitivePatterns {
		if pattern.MatchString(domainLower) {
			profile.SensitivePatterns++
			break
		}
	}

	for _, pattern := range ai.speedPatterns {
		if pattern.MatchString(domainLower) {
			profile.SpeedSensitive++
			break
		}
	}

	if isSensitive {
		profile.SensitivePatterns++
	}
	if isSpeedCritical {
		profile.SpeedSensitive++
	}

	// Update category and confidence
	ai.updateCategory(profile)

	// Save periodically
	if profile.ConnectionCount%20 == 0 {
		go ai.saveData()
	}
}

// updateCategory updates the category based on learned behavior
func (ai *SplitTunnelAI) updateCategory(profile *AppProfile) {
	if profile.ConnectionCount < 10 {
		profile.Category = CategoryLearning
		profile.Confidence = float64(profile.ConnectionCount) / 10.0 * 0.5
		return
	}

	// Calculate ratios
	sensitiveRatio := float64(profile.SensitivePatterns) / float64(profile.ConnectionCount)
	speedRatio := float64(profile.SpeedSensitive) / float64(profile.ConnectionCount)

	// Decision logic
	if sensitiveRatio > 0.3 {
		profile.Category = CategoryAlwaysTor
		profile.Confidence = 0.5 + sensitiveRatio*0.5
	} else if speedRatio > 0.5 && sensitiveRatio < 0.1 {
		profile.Category = CategoryNeverTor
		profile.Confidence = 0.5 + speedRatio*0.4
	} else {
		// Mixed usage - default to Tor for safety
		profile.Category = CategoryAlwaysTor
		profile.Confidence = 0.6
	}

	// Cap confidence
	if profile.Confidence > 0.95 {
		profile.Confidence = 0.95
	}
}

// SetAppCategory manually sets an app's category
func (ai *SplitTunnelAI) SetAppCategory(appName string, alwaysTor bool) {
	ai.mu.Lock()
	defer ai.mu.Unlock()

	profile, exists := ai.appProfiles[appName]
	if !exists {
		profile = &AppProfile{
			Name:     appName,
			Category: CategoryUserDefined,
		}
		ai.appProfiles[appName] = profile
	}

	profile.Category = CategoryUserDefined
	if alwaysTor {
		profile.SensitivePatterns = 100 // Force Tor
	} else {
		profile.SpeedSensitive = 100 // Force direct
	}
	profile.Confidence = 1.0
	profile.LastUpdated = time.Now()

	go ai.saveData()
}

// AddSensitiveDomain adds a domain to always route through Tor
func (ai *SplitTunnelAI) AddSensitiveDomain(domain string) {
	ai.mu.Lock()
	defer ai.mu.Unlock()
	ai.sensitiveDomains[strings.ToLower(domain)] = true
	go ai.saveData()
}

// AddSpeedDomain adds a domain to prefer direct connection
func (ai *SplitTunnelAI) AddSpeedDomain(domain string) {
	ai.mu.Lock()
	defer ai.mu.Unlock()
	ai.speedDomains[strings.ToLower(domain)] = true
	go ai.saveData()
}

// GetAppProfiles returns all learned app profiles
func (ai *SplitTunnelAI) GetAppProfiles() map[string]*AppProfile {
	ai.mu.RLock()
	defer ai.mu.RUnlock()

	result := make(map[string]*AppProfile)
	for k, v := range ai.appProfiles {
		result[k] = v
	}
	return result
}

// GetTopApps returns the top apps by connection count
func (ai *SplitTunnelAI) GetTopApps(count int) []*AppProfile {
	ai.mu.RLock()
	defer ai.mu.RUnlock()

	apps := make([]*AppProfile, 0, len(ai.appProfiles))
	for _, p := range ai.appProfiles {
		apps = append(apps, p)
	}

	sort.Slice(apps, func(i, j int) bool {
		return apps[i].ConnectionCount > apps[j].ConnectionCount
	})

	if count > len(apps) {
		count = len(apps)
	}
	return apps[:count]
}

// loadData loads saved AI data
func (ai *SplitTunnelAI) loadData() {
	// Load app profiles
	profilesPath := filepath.Join(ai.dataDir, "app_profiles.json")
	if data, err := os.ReadFile(profilesPath); err == nil {
		json.Unmarshal(data, &ai.appProfiles)
	}

	// Load custom domains
	customPath := filepath.Join(ai.dataDir, "custom_domains.json")
	if data, err := os.ReadFile(customPath); err == nil {
		var custom struct {
			Sensitive map[string]bool `json:"sensitive"`
			Speed     map[string]bool `json:"speed"`
		}
		if json.Unmarshal(data, &custom) == nil {
			for k, v := range custom.Sensitive {
				ai.sensitiveDomains[k] = v
			}
			for k, v := range custom.Speed {
				ai.speedDomains[k] = v
			}
		}
	}
}

// saveData persists AI data to disk
func (ai *SplitTunnelAI) saveData() {
	ai.mu.RLock()
	defer ai.mu.RUnlock()

	os.MkdirAll(ai.dataDir, 0700)

	// Save app profiles
	if data, err := json.MarshalIndent(ai.appProfiles, "", "  "); err == nil {
		os.WriteFile(filepath.Join(ai.dataDir, "app_profiles.json"), data, 0600)
	}

	// Save custom domains
	custom := struct {
		Sensitive map[string]bool `json:"sensitive"`
		Speed     map[string]bool `json:"speed"`
	}{
		Sensitive: ai.sensitiveDomains,
		Speed:     ai.speedDomains,
	}
	if data, err := json.MarshalIndent(custom, "", "  "); err == nil {
		os.WriteFile(filepath.Join(ai.dataDir, "custom_domains.json"), data, 0600)
	}
}

// EnableLearning enables/disables AI learning
func (ai *SplitTunnelAI) EnableLearning(enabled bool) {
	ai.mu.Lock()
	defer ai.mu.Unlock()
	ai.learningEnabled = enabled
}

// ResetLearning clears all learned data
func (ai *SplitTunnelAI) ResetLearning() {
	ai.mu.Lock()
	defer ai.mu.Unlock()

	// Keep user-defined, clear learned
	for name, profile := range ai.appProfiles {
		if profile.Category != CategoryUserDefined {
			delete(ai.appProfiles, name)
		}
	}

	go ai.saveData()
}

// Helper function
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
