package bypass

import (
	"net"
	"testing"
)

// TestGeoIPMatcherNil tests nil matcher behavior from user perspective
func TestGeoIPMatcherNil(t *testing.T) {
	// When no GeoIP database is available, matcher returns nil
	// This is a common scenario users will encounter
	var matcher *GeoIPMatcher = nil

	// Match should return false for nil matcher
	if country, matched := matcher.Match(net.ParseIP("8.8.8.8")); matched {
		t.Errorf("nil matcher should not match, got country %s", country)
	}

	// GetCountry should return empty for nil matcher
	if country := matcher.GetCountry(net.ParseIP("8.8.8.8")); country != "" {
		t.Errorf("nil matcher GetCountry should return empty, got %s", country)
	}

	// Close should be safe on nil matcher
	if err := matcher.Close(); err != nil {
		t.Errorf("nil matcher Close() should not error, got %v", err)
	}

	// GetBypassedCountries should return nil for nil matcher
	if countries := matcher.GetBypassedCountries(); countries != nil {
		t.Errorf("nil matcher GetBypassedCountries should return nil, got %v", countries)
	}
}

// TestGeoIPMatcherNoDatabase tests creating matcher without database
func TestGeoIPMatcherNoDatabase(t *testing.T) {
	// Creating with empty path and non-existent defaults should return nil, nil
	matcher, err := NewGeoIPMatcher("", []string{"US", "DE"})

	// When no database is found, it should return nil without error
	if err != nil {
		t.Errorf("NewGeoIPMatcher() with no database should not error: %v", err)
	}

	// Matcher will be nil when database is not found
	if matcher != nil {
		// If a database was found, verify it works
		defer matcher.Close()

		// Test GetBypassedCountries
		countries := matcher.GetBypassedCountries()
		if len(countries) != 2 {
			t.Errorf("expected 2 bypassed countries, got %d", len(countries))
		}
	}
}

// TestGeoIPMatcherInvalidPath tests creating matcher with invalid path
func TestGeoIPMatcherInvalidPath(t *testing.T) {
	// Creating with invalid path should return error
	_, err := NewGeoIPMatcher("/nonexistent/path/to/database.mmdb", []string{"US"})
	if err == nil {
		t.Error("NewGeoIPMatcher() with invalid path should error")
	}
}

// TestGeoIPMatcherCountryManagement tests adding/removing countries
// This test simulates a user modifying the bypass list at runtime
func TestGeoIPMatcherCountryManagement(t *testing.T) {
	// We need to test the methods even without a real database
	// Create a mock-like scenario using the struct directly

	matcher := &GeoIPMatcher{
		db:        nil, // No database
		countries: make(map[string]bool),
	}

	// Initially no countries
	countries := matcher.GetBypassedCountries()
	if len(countries) != 0 {
		t.Errorf("expected 0 countries initially, got %d", len(countries))
	}

	// User adds countries
	matcher.AddCountry("US")
	matcher.AddCountry("DE")
	matcher.AddCountry("UK")

	countries = matcher.GetBypassedCountries()
	if len(countries) != 3 {
		t.Errorf("expected 3 countries, got %d", len(countries))
	}

	// User removes a country
	matcher.RemoveCountry("UK")

	countries = matcher.GetBypassedCountries()
	if len(countries) != 2 {
		t.Errorf("expected 2 countries after removal, got %d", len(countries))
	}

	// Verify specific countries
	countryMap := make(map[string]bool)
	for _, c := range countries {
		countryMap[c] = true
	}

	if !countryMap["US"] {
		t.Error("US should still be in bypass list")
	}
	if !countryMap["DE"] {
		t.Error("DE should still be in bypass list")
	}
	if countryMap["UK"] {
		t.Error("UK should not be in bypass list")
	}
}

// TestGeoIPMatcherMatchWithoutDB tests Match behavior without database
func TestGeoIPMatcherMatchWithoutDB(t *testing.T) {
	matcher := &GeoIPMatcher{
		db:        nil,
		countries: map[string]bool{"US": true},
	}

	// Without a database, Match should return false
	_, matched := matcher.Match(net.ParseIP("8.8.8.8"))
	if matched {
		t.Error("Match without database should return false")
	}
}

// TestGeoIPMatcherAddDuplicateCountry tests adding the same country twice
func TestGeoIPMatcherAddDuplicateCountry(t *testing.T) {
	matcher := &GeoIPMatcher{
		db:        nil,
		countries: make(map[string]bool),
	}

	// Add same country multiple times
	matcher.AddCountry("US")
	matcher.AddCountry("US")
	matcher.AddCountry("US")

	countries := matcher.GetBypassedCountries()
	if len(countries) != 1 {
		t.Errorf("duplicate adds should result in 1 country, got %d", len(countries))
	}
}

// TestGeoIPMatcherRemoveNonexistent tests removing a country that doesn't exist
func TestGeoIPMatcherRemoveNonexistent(t *testing.T) {
	matcher := &GeoIPMatcher{
		db:        nil,
		countries: map[string]bool{"US": true},
	}

	// Should not panic when removing non-existent country
	matcher.RemoveCountry("NONEXISTENT")

	countries := matcher.GetBypassedCountries()
	if len(countries) != 1 {
		t.Errorf("expected 1 country after removing nonexistent, got %d", len(countries))
	}
}
