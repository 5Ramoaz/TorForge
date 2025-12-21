// Package netfilter - DNS-over-Tor resolver
package netfilter

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/jery0843/torforge/pkg/config"
	"github.com/jery0843/torforge/pkg/logger"
	"github.com/miekg/dns"
)

// DNSResolver is a DNS server that routes queries through Tor
type DNSResolver struct {
	cfg         *config.TorConfig
	bypassCfg   *config.BypassConfig
	server      *dns.Server
	torUpstream string
	fallback    string
	cache       *dnsCache
	running     bool
	mu          sync.RWMutex
}

type dnsCache struct {
	entries map[string]*dnsCacheEntry
	mu      sync.RWMutex
	maxAge  time.Duration
}

type dnsCacheEntry struct {
	response  *dns.Msg
	timestamp time.Time
}

// NewDNSResolver creates a new DNS resolver
func NewDNSResolver(torCfg *config.TorConfig, bypassCfg *config.BypassConfig) *DNSResolver {
	return &DNSResolver{
		cfg:         torCfg,
		bypassCfg:   bypassCfg,
		torUpstream: fmt.Sprintf("127.0.0.1:%d", torCfg.DNSPort),
		fallback:    "9.9.9.9:53", // Quad9 as fallback (should go through Tor)
		cache: &dnsCache{
			entries: make(map[string]*dnsCacheEntry),
			maxAge:  5 * time.Minute,
		},
	}
}

// Start starts the DNS resolver
func (r *DNSResolver) Start(listenPort int) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.running {
		return fmt.Errorf("DNS resolver already running")
	}

	log := logger.WithComponent("dns")
	addr := fmt.Sprintf("127.0.0.1:%d", listenPort)

	// Create DNS handler
	dns.HandleFunc(".", r.handleDNS)

	// Start UDP server
	r.server = &dns.Server{
		Addr: addr,
		Net:  "udp",
	}

	go func() {
		log.Info().Str("addr", addr).Msg("DNS resolver listening")
		if err := r.server.ListenAndServe(); err != nil {
			log.Error().Err(err).Msg("DNS server error")
		}
	}()

	r.running = true
	return nil
}

// Stop stops the DNS resolver
func (r *DNSResolver) Stop() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.running {
		return nil
	}

	if r.server != nil {
		r.server.Shutdown()
	}

	r.running = false
	return nil
}

func (r *DNSResolver) handleDNS(w dns.ResponseWriter, req *dns.Msg) {
	log := logger.WithComponent("dns")

	if len(req.Question) == 0 {
		dns.HandleFailed(w, req)
		return
	}

	question := req.Question[0]
	domain := strings.TrimSuffix(question.Name, ".")

	log.Debug().
		Str("domain", domain).
		Str("type", dns.TypeToString[question.Qtype]).
		Msg("DNS query")

	// Check bypass rules
	if r.shouldBypass(domain) {
		log.Debug().Str("domain", domain).Msg("bypassing DNS (clearnet)")
		r.resolveBypass(w, req, domain)
		return
	}

	// Check cache
	if cached := r.cache.get(domain, question.Qtype); cached != nil {
		cached.Id = req.Id
		w.WriteMsg(cached)
		log.Debug().Str("domain", domain).Msg("DNS cache hit")
		return
	}

	// Resolve through Tor's DNS
	r.resolveTor(w, req, domain)
}

func (r *DNSResolver) shouldBypass(domain string) bool {
	if r.bypassCfg == nil || !r.bypassCfg.Enabled {
		return false
	}

	for _, pattern := range r.bypassCfg.Domains {
		if matchDomain(pattern, domain) {
			return true
		}
	}

	return false
}

func matchDomain(pattern, domain string) bool {
	// Handle wildcard patterns
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // Remove "*"
		return strings.HasSuffix(domain, suffix) || domain == pattern[2:]
	}

	return pattern == domain
}

func (r *DNSResolver) resolveTor(w dns.ResponseWriter, req *dns.Msg, domain string) {
	log := logger.WithComponent("dns")

	// Create client to query Tor's DNS port
	client := &dns.Client{
		Net:     "udp",
		Timeout: 10 * time.Second,
	}

	resp, _, err := client.Exchange(req, r.torUpstream)
	if err != nil {
		log.Warn().Err(err).Str("domain", domain).Msg("Tor DNS query failed")

		// Return SERVFAIL
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeServerFailure)
		w.WriteMsg(m)
		return
	}

	// Cache the response
	if resp.Rcode == dns.RcodeSuccess {
		r.cache.set(domain, req.Question[0].Qtype, resp)
	}

	w.WriteMsg(resp)
}

func (r *DNSResolver) resolveBypass(w dns.ResponseWriter, req *dns.Msg, domain string) {
	log := logger.WithComponent("dns")

	// For bypass domains, we could either:
	// 1. Return a fake response (anti-leak)
	// 2. Allow clearnet resolution (local services)

	// Option 2: Direct resolution for local domains
	client := &dns.Client{
		Net:     "udp",
		Timeout: 5 * time.Second,
	}

	// Try to resolve via system resolver (for local domains)
	resp, _, err := client.Exchange(req, "127.0.0.53:53") // systemd-resolved
	if err != nil {
		// Fallback to localhost
		resp, _, err = client.Exchange(req, "127.0.0.1:53")
		if err != nil {
			log.Debug().Err(err).Str("domain", domain).Msg("local DNS failed, returning NXDOMAIN")
			m := new(dns.Msg)
			m.SetRcode(req, dns.RcodeNameError)
			w.WriteMsg(m)
			return
		}
	}

	w.WriteMsg(resp)
}

// Cache methods
func (c *dnsCache) get(domain string, qtype uint16) *dns.Msg {
	c.mu.RLock()
	defer c.mu.RUnlock()

	key := fmt.Sprintf("%s:%d", domain, qtype)
	entry, ok := c.entries[key]
	if !ok {
		return nil
	}

	if time.Since(entry.timestamp) > c.maxAge {
		return nil
	}

	// Return a copy
	return entry.response.Copy()
}

func (c *dnsCache) set(domain string, qtype uint16, msg *dns.Msg) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := fmt.Sprintf("%s:%d", domain, qtype)
	c.entries[key] = &dnsCacheEntry{
		response:  msg.Copy(),
		timestamp: time.Now(),
	}
}

// LeakCheck performs a DNS leak check
func LeakCheck(ctx context.Context, torDNSPort int) (*LeakCheckResult, error) {
	log := logger.WithComponent("leak-check")
	result := &LeakCheckResult{
		Timestamp: time.Now(),
		Tests:     make([]LeakTest, 0),
	}

	// Test 1: Check if DNS goes through Tor
	log.Info().Msg("testing DNS leak protection...")

	// Query a known Tor check domain
	client := &dns.Client{
		Net:     "udp",
		Timeout: 10 * time.Second,
	}

	msg := new(dns.Msg)
	msg.SetQuestion("check.torproject.org.", dns.TypeA)

	resp, _, err := client.Exchange(msg, fmt.Sprintf("127.0.0.1:%d", torDNSPort))
	if err != nil {
		result.Tests = append(result.Tests, LeakTest{
			Name:   "DNS through Tor",
			Passed: false,
			Error:  err.Error(),
		})
	} else {
		result.Tests = append(result.Tests, LeakTest{
			Name:    "DNS through Tor",
			Passed:  resp.Rcode == dns.RcodeSuccess,
			Details: fmt.Sprintf("Response code: %s", dns.RcodeToString[resp.Rcode]),
		})
	}

	// Test 2: Check for DNS leaks to system resolver
	// This attempts to use the default system DNS
	conn, err := net.DialTimeout("udp", "8.8.8.8:53", 3*time.Second)
	if err == nil {
		conn.Close()
		// If we can reach 8.8.8.8:53, might be a leak
		result.Tests = append(result.Tests, LeakTest{
			Name:    "Direct DNS blocked",
			Passed:  false,
			Details: "Direct connection to 8.8.8.8:53 succeeded (potential leak)",
		})
	} else {
		result.Tests = append(result.Tests, LeakTest{
			Name:   "Direct DNS blocked",
			Passed: true,
		})
	}

	// Calculate overall pass
	result.Passed = true
	for _, t := range result.Tests {
		if !t.Passed {
			result.Passed = false
			break
		}
	}

	return result, nil
}

// LeakCheckResult contains DNS leak check results
type LeakCheckResult struct {
	Timestamp time.Time
	Passed    bool
	Tests     []LeakTest
}

// LeakTest represents a single leak test
type LeakTest struct {
	Name    string
	Passed  bool
	Details string
	Error   string
}
