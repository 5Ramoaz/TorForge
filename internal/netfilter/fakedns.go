// Package netfilter provides FakeDNS for leak prevention
package netfilter

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/jery0843/torforge/pkg/logger"
	"github.com/miekg/dns"
)

// FakeDNSServer provides fake DNS responses to prevent leaks
// It returns internal IPs for all queries, which are then routed through Tor
type FakeDNSServer struct {
	server      *dns.Server
	mu          sync.RWMutex
	running     bool
	listenAddr  string
	fakeSubnet  *net.IPNet
	mappings    map[string]net.IP // domain -> fake IP
	reverseMaps map[string]string // fake IP -> domain
	nextIP      net.IP
	ttl         uint32
}

// FakeDNSConfig configures the FakeDNS server
type FakeDNSConfig struct {
	ListenAddr string
	FakeSubnet string // e.g., "198.18.0.0/15" (reserved for benchmarking)
	TTL        uint32
}

// NewFakeDNSServer creates a new FakeDNS server
func NewFakeDNSServer(cfg *FakeDNSConfig) (*FakeDNSServer, error) {
	_, subnet, err := net.ParseCIDR(cfg.FakeSubnet)
	if err != nil {
		return nil, fmt.Errorf("invalid fake subnet: %w", err)
	}

	// Start with first IP in subnet
	startIP := make(net.IP, len(subnet.IP))
	copy(startIP, subnet.IP)
	incrementIP(startIP)

	return &FakeDNSServer{
		listenAddr:  cfg.ListenAddr,
		fakeSubnet:  subnet,
		mappings:    make(map[string]net.IP),
		reverseMaps: make(map[string]string),
		nextIP:      startIP,
		ttl:         cfg.TTL,
	}, nil
}

// Start starts the FakeDNS server
func (f *FakeDNSServer) Start() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.running {
		return fmt.Errorf("FakeDNS already running")
	}

	log := logger.WithComponent("fakedns")
	log.Info().Str("addr", f.listenAddr).Msg("starting FakeDNS server")

	f.server = &dns.Server{
		Addr:    f.listenAddr,
		Net:     "udp",
		Handler: dns.HandlerFunc(f.handleDNS),
	}

	go func() {
		if err := f.server.ListenAndServe(); err != nil {
			log.Error().Err(err).Msg("FakeDNS server error")
		}
	}()

	f.running = true
	return nil
}

// Stop stops the FakeDNS server
func (f *FakeDNSServer) Stop() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if !f.running {
		return nil
	}

	if f.server != nil {
		f.server.Shutdown()
	}

	f.running = false
	return nil
}

func (f *FakeDNSServer) handleDNS(w dns.ResponseWriter, r *dns.Msg) {
	log := logger.WithComponent("fakedns")

	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	for _, q := range r.Question {
		switch q.Qtype {
		case dns.TypeA:
			fakeIP := f.getFakeIP(q.Name)
			rr := &dns.A{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    f.ttl,
				},
				A: fakeIP,
			}
			m.Answer = append(m.Answer, rr)
			log.Debug().Str("domain", q.Name).Str("fake_ip", fakeIP.String()).Msg("FakeDNS response")

		case dns.TypeAAAA:
			// Return empty for IPv6 to force IPv4
			// This prevents IPv6 leaks

		case dns.TypePTR:
			// Reverse lookup
			domain := f.getReverseDomain(q.Name)
			if domain != "" {
				rr := &dns.PTR{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypePTR,
						Class:  dns.ClassINET,
						Ttl:    f.ttl,
					},
					Ptr: domain,
				}
				m.Answer = append(m.Answer, rr)
			}
		}
	}

	w.WriteMsg(m)
}

// getFakeIP returns a fake IP for the domain, creating one if needed
func (f *FakeDNSServer) getFakeIP(domain string) net.IP {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Normalize domain
	domain = dns.CanonicalName(domain)

	// Check if already mapped
	if ip, ok := f.mappings[domain]; ok {
		return ip
	}

	// Allocate new fake IP
	fakeIP := make(net.IP, len(f.nextIP))
	copy(fakeIP, f.nextIP)

	f.mappings[domain] = fakeIP
	f.reverseMaps[fakeIP.String()] = domain

	// Increment for next allocation
	incrementIP(f.nextIP)

	return fakeIP
}

// getReverseDomain returns the domain for a fake IP
func (f *FakeDNSServer) getReverseDomain(ptrName string) string {
	f.mu.RLock()
	defer f.mu.RUnlock()

	// Convert PTR format (e.g., "1.0.18.198.in-addr.arpa.") to IP
	ip := ptrToIP(ptrName)
	if ip == "" {
		return ""
	}

	return f.reverseMaps[ip]
}

// GetDomainForIP returns the real domain for a fake IP
func (f *FakeDNSServer) GetDomainForIP(ip net.IP) string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.reverseMaps[ip.String()]
}

// IsFakeIP checks if an IP is in our fake subnet
func (f *FakeDNSServer) IsFakeIP(ip net.IP) bool {
	return f.fakeSubnet.Contains(ip)
}

// GetMappingCount returns the number of active mappings
func (f *FakeDNSServer) GetMappingCount() int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return len(f.mappings)
}

// CleanupOldMappings removes mappings older than duration
func (f *FakeDNSServer) CleanupOldMappings(maxAge time.Duration) {
	// In a full implementation, we'd track timestamps
	// For now, this is a placeholder
}

// incrementIP increments an IP address by 1
func incrementIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] > 0 {
			break
		}
	}
}

// ptrToIP converts PTR record name to IP string
func ptrToIP(ptr string) string {
	// Format: "1.0.18.198.in-addr.arpa."
	// Remove suffix
	ptr = dns.CanonicalName(ptr)
	if len(ptr) < 14 {
		return ""
	}

	// Remove ".in-addr.arpa."
	if ptr[len(ptr)-14:] != ".in-addr.arpa." {
		return ""
	}
	ptr = ptr[:len(ptr)-14]

	// Split and reverse
	parts := splitDNSName(ptr)
	if len(parts) != 4 {
		return ""
	}

	// Reverse order
	return fmt.Sprintf("%s.%s.%s.%s", parts[3], parts[2], parts[1], parts[0])
}

func splitDNSName(s string) []string {
	var parts []string
	var current string
	for _, c := range s {
		if c == '.' {
			if current != "" {
				parts = append(parts, current)
				current = ""
			}
		} else {
			current += string(c)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}
	return parts
}
