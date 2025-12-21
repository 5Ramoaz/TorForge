// Circuit management for Tor
package tor

import (
	"sync"
	"time"

	"github.com/cretz/bine/tor"
	"github.com/jery0843/torforge/pkg/logger"
)

// CircuitManager manages Tor circuits
type CircuitManager struct {
	tor            *tor.Tor
	circuits       map[string]*Circuit
	mu             sync.RWMutex
	stopCh         chan struct{}
	rotating       bool
	rotateInterval time.Duration
	rotateBytes    int64
}

// Circuit represents a Tor circuit
type Circuit struct {
	ID        string
	Status    string
	CreatedAt time.Time
	BytesSent int64
	BytesRecv int64
	Path      []string // Relay fingerprints
	Purpose   string
	Domain    string // For per-domain isolation
	ExitNode  string
	Latency   time.Duration
	LastUsed  time.Time
}

// NewCircuitManager creates a new circuit manager
func NewCircuitManager(t *tor.Tor) *CircuitManager {
	cm := &CircuitManager{
		tor:            t,
		circuits:       make(map[string]*Circuit),
		stopCh:         make(chan struct{}),
		rotateInterval: 10 * time.Minute,
		rotateBytes:    100 * 1024 * 1024, // 100MB
	}

	go cm.monitorLoop()
	return cm
}

// SetRotationPolicy sets circuit rotation policy
func (cm *CircuitManager) SetRotationPolicy(interval time.Duration, bytes int64) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.rotateInterval = interval
	cm.rotateBytes = bytes
}

// GetCount returns the number of active circuits
func (cm *CircuitManager) GetCount() int {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return len(cm.circuits)
}

// GetCircuits returns all active circuits
func (cm *CircuitManager) GetCircuits() []*Circuit {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	circuits := make([]*Circuit, 0, len(cm.circuits))
	for _, c := range cm.circuits {
		circuits = append(circuits, c)
	}
	return circuits
}

// CreateCircuit creates a new Tor circuit
func (cm *CircuitManager) CreateCircuit(purpose string) (*Circuit, error) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	log := logger.WithComponent("circuit")

	// Generate a local circuit ID
	circuitID := generateCircuitID()

	circuit := &Circuit{
		ID:        circuitID,
		Status:    "BUILDING",
		CreatedAt: time.Now(),
		Purpose:   purpose,
		LastUsed:  time.Now(),
	}

	cm.circuits[circuitID] = circuit
	log.Info().Str("circuit_id", circuitID).Str("purpose", purpose).Msg("created new circuit")

	logger.CircuitEvent(circuitID, "created")

	return circuit, nil
}

// CloseCircuit closes a specific circuit
func (cm *CircuitManager) CloseCircuit(id string) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	log := logger.WithComponent("circuit")

	delete(cm.circuits, id)
	log.Info().Str("circuit_id", id).Msg("closed circuit")
	logger.CircuitEvent(id, "closed")

	return nil
}

// RotateCircuits closes all circuits and creates new ones
func (cm *CircuitManager) RotateCircuits() error {
	cm.mu.Lock()
	if cm.rotating {
		cm.mu.Unlock()
		return nil
	}
	cm.rotating = true
	cm.mu.Unlock()

	defer func() {
		cm.mu.Lock()
		cm.rotating = false
		cm.mu.Unlock()
	}()

	log := logger.WithComponent("circuit")
	log.Info().Msg("rotating circuits")

	// Get current circuit IDs
	cm.mu.RLock()
	ids := make([]string, 0, len(cm.circuits))
	for id := range cm.circuits {
		ids = append(ids, id)
	}
	cm.mu.RUnlock()

	// Close old circuits
	for _, id := range ids {
		if err := cm.CloseCircuit(id); err != nil {
			log.Warn().Err(err).Str("circuit_id", id).Msg("failed to close circuit")
		}
	}

	// Signal new identity via Tor control
	if cm.tor != nil && cm.tor.Control != nil {
		if err := cm.tor.Control.Signal("NEWNYM"); err != nil {
			log.Warn().Err(err).Msg("failed to signal new identity")
		}
	}

	log.Info().Msg("circuits rotated, new identity requested")
	return nil
}

// GetCircuitForDomain returns or creates a circuit for a specific domain
func (cm *CircuitManager) GetCircuitForDomain(domain string) (*Circuit, error) {
	cm.mu.RLock()
	for _, c := range cm.circuits {
		if c.Domain == domain && c.Status == "BUILT" {
			c.LastUsed = time.Now()
			cm.mu.RUnlock()
			return c, nil
		}
	}
	cm.mu.RUnlock()

	// Create new circuit for this domain
	circuit, err := cm.CreateCircuit("domain:" + domain)
	if err != nil {
		return nil, err
	}
	circuit.Domain = domain

	return circuit, nil
}

// Stop stops the circuit manager
func (cm *CircuitManager) Stop() {
	close(cm.stopCh)
}

func (cm *CircuitManager) monitorLoop() {
	log := logger.WithComponent("circuit")
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-cm.stopCh:
			log.Debug().Msg("circuit monitor stopped")
			return
		case <-ticker.C:
			cm.updateCircuitStatus()
			cm.checkRotation()
		}
	}
}

func (cm *CircuitManager) updateCircuitStatus() {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if cm.tor == nil || cm.tor.Control == nil {
		return
	}

	// Query circuit status from Tor
	info, err := cm.tor.Control.GetInfo("circuit-status")
	if err != nil {
		return
	}

	// Parse circuit status
	for _, entry := range info {
		parseCircuitStatus(entry.Val, cm.circuits)
	}
}

func (cm *CircuitManager) checkRotation() {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	now := time.Now()
	for _, c := range cm.circuits {
		// Time-based rotation
		if now.Sub(c.CreatedAt) > cm.rotateInterval {
			go cm.RotateCircuits()
			return
		}

		// Traffic-based rotation
		if c.BytesSent+c.BytesRecv > cm.rotateBytes {
			go cm.RotateCircuits()
			return
		}
	}
}

var circuitCounter int64
var counterMu sync.Mutex

func generateCircuitID() string {
	counterMu.Lock()
	defer counterMu.Unlock()
	circuitCounter++
	return "local-" + time.Now().Format("150405") + "-" + string('0'+byte(circuitCounter%10))
}

// parseCircuitID extracts circuit ID from EXTENDCIRCUIT response
func parseCircuitID(reply string) string {
	// Response format: "EXTENDED <circuitID>"
	if len(reply) < 10 {
		return ""
	}

	// Find the ID after "EXTENDED "
	for i := 0; i < len(reply)-8; i++ {
		if reply[i:i+8] == "EXTENDED" {
			id := ""
			for j := i + 9; j < len(reply); j++ {
				if reply[j] >= '0' && reply[j] <= '9' {
					id += string(reply[j])
				} else if reply[j] == ' ' || reply[j] == '\n' || reply[j] == '\r' {
					break
				}
			}
			return id
		}
	}

	// Fallback: just return first number found
	id := ""
	for _, c := range reply {
		if c >= '0' && c <= '9' {
			id += string(c)
		} else if len(id) > 0 {
			break
		}
	}
	return id
}

// parseCircuitStatus parses circuit status from Tor
func parseCircuitStatus(statusLine string, circuits map[string]*Circuit) {
	// Format: <circuitID> <status> <path> <buildFlags> <purpose>...
	// Example: 16 BUILT $FINGERPRINT1,$FINGERPRINT2 BUILD_FLAGS=... PURPOSE=GENERAL

	// Simple parsing
	var id, status string
	parts := splitFields(statusLine)
	if len(parts) >= 2 {
		id = parts[0]
		status = parts[1]
	}

	if id == "" {
		return
	}

	if circuit, ok := circuits[id]; ok {
		circuit.Status = status
	}
}

func splitFields(s string) []string {
	var fields []string
	var current string

	for _, c := range s {
		if c == ' ' || c == '\t' || c == '\n' {
			if current != "" {
				fields = append(fields, current)
				current = ""
			}
		} else {
			current += string(c)
		}
	}
	if current != "" {
		fields = append(fields, current)
	}
	return fields
}

// CircuitStats holds circuit statistics
type CircuitStats struct {
	TotalCreated   int64
	TotalClosed    int64
	ActiveCount    int
	AverageLatency time.Duration
	TotalBytesSent int64
	TotalBytesRecv int64
}

// GetStats returns circuit statistics
func (cm *CircuitManager) GetStats() CircuitStats {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	stats := CircuitStats{
		ActiveCount: len(cm.circuits),
	}

	for _, c := range cm.circuits {
		stats.TotalBytesSent += c.BytesSent
		stats.TotalBytesRecv += c.BytesRecv
	}

	return stats
}
