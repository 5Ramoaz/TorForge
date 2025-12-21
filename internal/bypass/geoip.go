// Package bypass - GeoIP matching for bypass rules
package bypass

import (
	"net"
	"sync"

	"github.com/jery0843/torforge/pkg/logger"
	"github.com/oschwald/geoip2-golang"
)

// GeoIPMatcher matches IPs to countries
type GeoIPMatcher struct {
	db        *geoip2.Reader
	countries map[string]bool
	mu        sync.RWMutex
}

// NewGeoIPMatcher creates a new GeoIP matcher
func NewGeoIPMatcher(dbPath string, countries []string) (*GeoIPMatcher, error) {
	log := logger.WithComponent("geoip")

	if dbPath == "" {
		// Try default locations
		defaultPaths := []string{
			"/usr/share/GeoIP/GeoLite2-Country.mmdb",
			"/var/lib/GeoIP/GeoLite2-Country.mmdb",
			"./GeoLite2-Country.mmdb",
		}
		for _, p := range defaultPaths {
			db, err := geoip2.Open(p)
			if err == nil {
				dbPath = p
				db.Close()
				break
			}
		}
	}

	if dbPath == "" {
		log.Warn().Msg("GeoIP database not found, country-based bypass disabled")
		return nil, nil
	}

	db, err := geoip2.Open(dbPath)
	if err != nil {
		return nil, err
	}

	// Build country set
	countrySet := make(map[string]bool)
	for _, c := range countries {
		countrySet[c] = true
	}

	log.Info().
		Str("database", dbPath).
		Int("countries", len(countries)).
		Msg("GeoIP matcher initialized")

	return &GeoIPMatcher{
		db:        db,
		countries: countrySet,
	}, nil
}

// Match checks if an IP is in one of the configured countries
func (g *GeoIPMatcher) Match(ip net.IP) (string, bool) {
	if g == nil || g.db == nil {
		return "", false
	}

	g.mu.RLock()
	defer g.mu.RUnlock()

	record, err := g.db.Country(ip)
	if err != nil {
		return "", false
	}

	country := record.Country.IsoCode
	if g.countries[country] {
		return country, true
	}

	return "", false
}

// GetCountry returns the country code for an IP
func (g *GeoIPMatcher) GetCountry(ip net.IP) string {
	if g == nil || g.db == nil {
		return ""
	}

	g.mu.RLock()
	defer g.mu.RUnlock()

	record, err := g.db.Country(ip)
	if err != nil {
		return ""
	}

	return record.Country.IsoCode
}

// AddCountry adds a country to the bypass list
func (g *GeoIPMatcher) AddCountry(code string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.countries[code] = true
}

// RemoveCountry removes a country from the bypass list
func (g *GeoIPMatcher) RemoveCountry(code string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.countries, code)
}

// Close closes the GeoIP database
func (g *GeoIPMatcher) Close() error {
	if g == nil || g.db == nil {
		return nil
	}
	return g.db.Close()
}

// GetBypassedCountries returns the list of bypassed countries
func (g *GeoIPMatcher) GetBypassedCountries() []string {
	if g == nil {
		return nil
	}

	g.mu.RLock()
	defer g.mu.RUnlock()

	countries := make([]string, 0, len(g.countries))
	for c := range g.countries {
		countries = append(countries, c)
	}
	return countries
}
