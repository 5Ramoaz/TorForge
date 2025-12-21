// Package bypass provides smart bypass rules for TorForge
package bypass

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"

	"github.com/jery0843/torforge/pkg/config"
	"github.com/jery0843/torforge/pkg/logger"
)

// Engine manages bypass rules
type Engine struct {
	cfg            *config.BypassConfig
	domainPatterns []*regexp.Regexp
	cidrNets       []*net.IPNet
	protocols      map[string]bool
	applications   map[string]bool
	customRules    []Rule
	geoIP          *GeoIPMatcher
	mu             sync.RWMutex
}

// Rule represents a bypass rule
type Rule struct {
	Name        string
	Type        RuleType
	Pattern     string
	Action      Action
	Description string
	compiled    interface{} // Compiled pattern (regexp, IPNet, etc.)
}

// RuleType defines the type of bypass rule
type RuleType string

const (
	RuleTypeDomain   RuleType = "domain"
	RuleTypeCIDR     RuleType = "cidr"
	RuleTypePort     RuleType = "port"
	RuleTypeProtocol RuleType = "protocol"
	RuleTypeApp      RuleType = "application"
	RuleTypeGeoIP    RuleType = "geoip"
)

// Action defines what to do with matched traffic
type Action string

const (
	ActionBypass Action = "bypass" // Don't route through Tor
	ActionBlock  Action = "block"  // Block completely
	ActionTor    Action = "tor"    // Force through Tor (default)
)

// MatchResult contains the result of a rule match
type MatchResult struct {
	Matched bool
	Rule    *Rule
	Action  Action
	Reason  string
}

// NewEngine creates a new bypass engine
func NewEngine(cfg *config.BypassConfig) (*Engine, error) {
	e := &Engine{
		cfg:          cfg,
		protocols:    make(map[string]bool),
		applications: make(map[string]bool),
	}

	if err := e.compileRules(); err != nil {
		return nil, err
	}

	return e, nil
}

func (e *Engine) compileRules() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	log := logger.WithComponent("bypass")

	// Compile domain patterns
	for _, pattern := range e.cfg.Domains {
		re, err := compileGlobToRegex(pattern)
		if err != nil {
			log.Warn().Err(err).Str("pattern", pattern).Msg("invalid domain pattern")
			continue
		}
		e.domainPatterns = append(e.domainPatterns, re)
	}
	log.Debug().Int("count", len(e.domainPatterns)).Msg("compiled domain patterns")

	// Parse CIDR ranges
	for _, cidr := range e.cfg.CIDRs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Warn().Err(err).Str("cidr", cidr).Msg("invalid CIDR")
			continue
		}
		e.cidrNets = append(e.cidrNets, ipNet)
	}
	log.Debug().Int("count", len(e.cidrNets)).Msg("parsed CIDR ranges")

	// Build protocol set
	for _, proto := range e.cfg.Protocols {
		e.protocols[strings.ToLower(proto)] = true
	}

	// Build application set
	for _, app := range e.cfg.Applications {
		e.applications[strings.ToLower(app)] = true
	}

	// Compile custom rules
	for _, r := range e.cfg.CustomRules {
		rule := Rule{
			Name:        r.Name,
			Type:        RuleType(r.Type),
			Pattern:     r.Pattern,
			Action:      Action(r.Action),
			Description: r.Description,
		}

		if err := e.compileRule(&rule); err != nil {
			log.Warn().Err(err).Str("rule", r.Name).Msg("failed to compile rule")
			continue
		}

		e.customRules = append(e.customRules, rule)
	}

	// Initialize GeoIP if enabled
	if e.cfg.GeoIP.Enabled {
		geoIP, err := NewGeoIPMatcher(e.cfg.GeoIP.DatabasePath, e.cfg.GeoIP.Countries)
		if err != nil {
			log.Warn().Err(err).Msg("failed to initialize GeoIP")
		} else {
			e.geoIP = geoIP
		}
	}

	return nil
}

func (e *Engine) compileRule(r *Rule) error {
	switch r.Type {
	case RuleTypeDomain:
		re, err := compileGlobToRegex(r.Pattern)
		if err != nil {
			return err
		}
		r.compiled = re
	case RuleTypeCIDR:
		_, ipNet, err := net.ParseCIDR(r.Pattern)
		if err != nil {
			return err
		}
		r.compiled = ipNet
	}
	return nil
}

// MatchDomain checks if a domain matches any bypass rule
func (e *Engine) MatchDomain(domain string) MatchResult {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if !e.cfg.Enabled {
		return MatchResult{Matched: false}
	}

	domain = strings.ToLower(domain)

	// Check domain patterns
	for _, re := range e.domainPatterns {
		if re.MatchString(domain) {
			return MatchResult{
				Matched: true,
				Action:  ActionBypass,
				Reason:  fmt.Sprintf("matches pattern %s", re.String()),
			}
		}
	}

	// Check custom rules
	for _, rule := range e.customRules {
		if rule.Type == RuleTypeDomain {
			if re, ok := rule.compiled.(*regexp.Regexp); ok {
				if re.MatchString(domain) {
					return MatchResult{
						Matched: true,
						Rule:    &rule,
						Action:  rule.Action,
						Reason:  rule.Description,
					}
				}
			}
		}
	}

	return MatchResult{Matched: false}
}

// MatchIP checks if an IP matches any bypass rule
func (e *Engine) MatchIP(ip net.IP) MatchResult {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if !e.cfg.Enabled {
		return MatchResult{Matched: false}
	}

	// Check CIDR ranges
	for _, ipNet := range e.cidrNets {
		if ipNet.Contains(ip) {
			return MatchResult{
				Matched: true,
				Action:  ActionBypass,
				Reason:  fmt.Sprintf("matches CIDR %s", ipNet.String()),
			}
		}
	}

	// Check GeoIP
	if e.geoIP != nil {
		if country, ok := e.geoIP.Match(ip); ok {
			return MatchResult{
				Matched: true,
				Action:  ActionBypass,
				Reason:  fmt.Sprintf("matches country %s", country),
			}
		}
	}

	// Check custom rules
	for _, rule := range e.customRules {
		if rule.Type == RuleTypeCIDR {
			if ipNet, ok := rule.compiled.(*net.IPNet); ok {
				if ipNet.Contains(ip) {
					return MatchResult{
						Matched: true,
						Rule:    &rule,
						Action:  rule.Action,
						Reason:  rule.Description,
					}
				}
			}
		}
	}

	return MatchResult{Matched: false}
}

// MatchProtocol checks if a protocol should bypass
func (e *Engine) MatchProtocol(proto string) MatchResult {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if !e.cfg.Enabled {
		return MatchResult{Matched: false}
	}

	proto = strings.ToLower(proto)
	if e.protocols[proto] {
		return MatchResult{
			Matched: true,
			Action:  ActionBypass,
			Reason:  fmt.Sprintf("protocol %s is bypassed", proto),
		}
	}

	return MatchResult{Matched: false}
}

// MatchApplication checks if an application should bypass
func (e *Engine) MatchApplication(appName string) MatchResult {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if !e.cfg.Enabled {
		return MatchResult{Matched: false}
	}

	appName = strings.ToLower(appName)
	if e.applications[appName] {
		return MatchResult{
			Matched: true,
			Action:  ActionBypass,
			Reason:  fmt.Sprintf("application %s is bypassed", appName),
		}
	}

	return MatchResult{Matched: false}
}

// AddRule dynamically adds a bypass rule
func (e *Engine) AddRule(rule Rule) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	log := logger.WithComponent("bypass")

	if err := e.compileRule(&rule); err != nil {
		return err
	}

	e.customRules = append(e.customRules, rule)
	log.Info().Str("name", rule.Name).Str("type", string(rule.Type)).Msg("added bypass rule")

	return nil
}

// RemoveRule removes a bypass rule by name
func (e *Engine) RemoveRule(name string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()

	for i, r := range e.customRules {
		if r.Name == name {
			e.customRules = append(e.customRules[:i], e.customRules[i+1:]...)
			return true
		}
	}
	return false
}

// GetRules returns all active rules
func (e *Engine) GetRules() []Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()

	rules := make([]Rule, len(e.customRules))
	copy(rules, e.customRules)
	return rules
}

// compileGlobToRegex converts glob patterns to regex
func compileGlobToRegex(pattern string) (*regexp.Regexp, error) {
	// Escape special regex characters except * and ?
	var regexPattern strings.Builder
	regexPattern.WriteString("^")

	for _, c := range pattern {
		switch c {
		case '*':
			regexPattern.WriteString(".*")
		case '?':
			regexPattern.WriteString(".")
		case '.':
			regexPattern.WriteString(`\.`)
		case '[', ']', '(', ')', '{', '}', '^', '$', '+', '|', '\\':
			regexPattern.WriteRune('\\')
			regexPattern.WriteRune(c)
		default:
			regexPattern.WriteRune(c)
		}
	}

	regexPattern.WriteString("$")
	return regexp.Compile(regexPattern.String())
}
