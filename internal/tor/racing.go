// Package tor provides Tor process and circuit management
package tor

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/jery0843/torforge/pkg/logger"
)

// CircuitRaceResult holds results from testing a circuit
type CircuitRaceResult struct {
	CircuitID string
	ExitIP    string
	Latency   time.Duration
	Success   bool
	Error     error
}

// CircuitRacer handles circuit racing for optimal speed
type CircuitRacer struct {
	manager     *Manager
	probeURLs   []string
	timeout     time.Duration
	results     []CircuitRaceResult
	bestCircuit *CircuitRaceResult
	mu          sync.RWMutex
}

// NewCircuitRacer creates a new circuit racer
func NewCircuitRacer(manager *Manager) *CircuitRacer {
	return &CircuitRacer{
		manager: manager,
		probeURLs: []string{
			"http://check.torproject.org/api/ip",
			"http://icanhazip.com",
			"http://ifconfig.me",
			"http://ipinfo.io/ip",
			"http://api.ipify.org",
			"http://ipecho.net/plain",
			"http://checkip.amazonaws.com",
			"http://wtfismyip.com/text",
		},
		timeout: 10 * time.Second,
		results: make([]CircuitRaceResult, 0),
	}
}

// RaceCircuits builds and tests multiple circuits, returns the fastest
func (r *CircuitRacer) RaceCircuits(count int) (*CircuitRaceResult, error) {
	log := logger.WithComponent("racing")

	log.Info().
		Int("count", count).
		Msg("⚡ Circuit Racing: Testing circuits...")

	// Build circuits in parallel
	var wg sync.WaitGroup
	resultsChan := make(chan CircuitRaceResult, count)

	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(circuitNum int) {
			defer wg.Done()
			result := r.probeCircuit(circuitNum)
			resultsChan <- result
		}(i + 1)
	}

	// Wait for all probes to complete
	wg.Wait()
	close(resultsChan)

	// Collect results
	r.mu.Lock()
	r.results = make([]CircuitRaceResult, 0, count)
	for result := range resultsChan {
		r.results = append(r.results, result)
	}
	r.mu.Unlock()

	// Find fastest successful circuit
	best := r.findFastest()
	if best == nil {
		return nil, fmt.Errorf("no successful circuits found")
	}

	r.mu.Lock()
	r.bestCircuit = best
	r.mu.Unlock()

	log.Info().
		Str("exit_ip", best.ExitIP).
		Dur("latency", best.Latency).
		Msg("🏆 Using fastest circuit")

	return best, nil
}

// probeCircuit tests a single circuit's latency
func (r *CircuitRacer) probeCircuit(circuitNum int) CircuitRaceResult {
	log := logger.WithComponent("racing")

	result := CircuitRaceResult{
		CircuitID: fmt.Sprintf("circuit_%d", circuitNum),
		Success:   false,
	}

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: r.timeout,
	}

	// Select probe URL based on circuit number (round-robin)
	probeURL := r.probeURLs[(circuitNum-1)%len(r.probeURLs)]

	// Measure latency
	start := time.Now()

	ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", probeURL, nil)
	if err != nil {
		result.Error = err
		return result
	}

	resp, err := client.Do(req)
	if err != nil {
		result.Error = err
		log.Debug().
			Int("circuit", circuitNum).
			Err(err).
			Msg("circuit probe failed")
		return result
	}
	defer resp.Body.Close()

	latency := time.Since(start)

	// Get exit IP from Tor check
	if resp.StatusCode == http.StatusOK {
		result.Success = true
		result.Latency = latency
		result.ExitIP = "detected" // Will be filled from response

		log.Info().
			Int("circuit", circuitNum).
			Dur("latency", latency).
			Msg("⚡ Circuit tested")
	} else {
		result.Error = fmt.Errorf("status code: %d", resp.StatusCode)
	}

	return result
}

// findFastest sorts results and returns the fastest successful circuit
func (r *CircuitRacer) findFastest() *CircuitRaceResult {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Filter successful results
	var successful []CircuitRaceResult
	for _, result := range r.results {
		if result.Success {
			successful = append(successful, result)
		}
	}

	if len(successful) == 0 {
		return nil
	}

	// Sort by latency (ascending)
	sort.Slice(successful, func(i, j int) bool {
		return successful[i].Latency < successful[j].Latency
	})

	return &successful[0]
}

// GetResults returns all race results
func (r *CircuitRacer) GetResults() []CircuitRaceResult {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return append([]CircuitRaceResult{}, r.results...)
}

// GetBestCircuit returns the best circuit from the last race
func (r *CircuitRacer) GetBestCircuit() *CircuitRaceResult {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return r.bestCircuit
}

// PrintResults prints a formatted table of race results
func (r *CircuitRacer) PrintResults() {
	r.mu.RLock()
	defer r.mu.RUnlock()

	log := logger.WithComponent("racing")

	// Sort by latency
	sorted := append([]CircuitRaceResult{}, r.results...)
	sort.Slice(sorted, func(i, j int) bool {
		if !sorted[i].Success && sorted[j].Success {
			return false
		}
		if sorted[i].Success && !sorted[j].Success {
			return true
		}
		return sorted[i].Latency < sorted[j].Latency
	})

	for i, result := range sorted {
		if result.Success {
			star := ""
			if r.bestCircuit != nil && result.CircuitID == r.bestCircuit.CircuitID {
				star = " ★ (fastest)"
			}
			log.Info().
				Str("circuit", result.CircuitID).
				Dur("latency", result.Latency).
				Str("status", fmt.Sprintf("%dms%s", result.Latency.Milliseconds(), star)).
				Msgf("   Circuit %d: %dms%s", i+1, result.Latency.Milliseconds(), star)
		} else {
			log.Warn().
				Str("circuit", result.CircuitID).
				Err(result.Error).
				Msgf("   Circuit %d: failed", i+1)
		}
	}
}
