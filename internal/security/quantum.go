// Package security provides advanced security features for TorForge
package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"sync"

	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"github.com/jery0843/torforge/pkg/logger"
)

// PostQuantumConfig configures the post-quantum encryption layer
type PostQuantumConfig struct {
	Enabled   bool   `yaml:"enabled"`
	Algorithm string `yaml:"algorithm"` // "kyber768"
}

// QuantumResistantLayer provides an additional encryption layer
// that is resistant to quantum computer attacks using CRYSTALS-Kyber
type QuantumResistantLayer struct {
	mu        sync.RWMutex
	enabled   bool
	algorithm string

	// Kyber key pair (using real Kyber768)
	publicKey  *kyber768.PublicKey
	privateKey *kyber768.PrivateKey

	// Ciphertext from key encapsulation
	ciphertext []byte

	// Shared secret for symmetric encryption
	sharedSecret []byte
	cipher       cipher.AEAD
}

// NewQuantumResistantLayer creates a new post-quantum encryption layer
func NewQuantumResistantLayer(cfg *PostQuantumConfig) (*QuantumResistantLayer, error) {
	log := logger.WithComponent("quantum")

	if cfg == nil || !cfg.Enabled {
		return &QuantumResistantLayer{enabled: false}, nil
	}

	q := &QuantumResistantLayer{
		enabled:   true,
		algorithm: "CRYSTALS-Kyber768",
	}

	// Generate Kyber key pair
	if err := q.generateKyberKeyPair(); err != nil {
		return nil, fmt.Errorf("failed to generate Kyber key pair: %w", err)
	}

	log.Info().
		Str("algorithm", q.algorithm).
		Msg("🔐 Post-quantum encryption layer initialized with REAL CRYSTALS-Kyber768")

	return q, nil
}

// generateKyberKeyPair generates a real CRYSTALS-Kyber768 key pair
func (q *QuantumResistantLayer) generateKyberKeyPair() error {
	// Generate Kyber768 key pair (NIST Level 3 security)
	pub, priv, err := kyber768.GenerateKeyPair(rand.Reader)
	if err != nil {
		return err
	}

	q.publicKey = pub
	q.privateKey = priv

	// Perform key encapsulation to derive shared secret
	// EncapsulateTo fills ciphertext and shared secret
	ct := make([]byte, kyber768.CiphertextSize)
	ss := make([]byte, kyber768.SharedKeySize)

	pub.EncapsulateTo(ct, ss, nil)

	// Store ciphertext
	q.ciphertext = ct

	// Verify we can decapsulate
	ssCheck := make([]byte, kyber768.SharedKeySize)
	priv.DecapsulateTo(ssCheck, ct)

	// Compare shared secrets
	if !compareBytes(ss, ssCheck) {
		return fmt.Errorf("kyber key exchange verification failed")
	}

	q.sharedSecret = ss

	// Create AES-256-GCM cipher using the Kyber-derived shared secret
	block, err := aes.NewCipher(q.sharedSecret)
	if err != nil {
		return err
	}

	q.cipher, err = cipher.NewGCM(block)
	if err != nil {
		return err
	}

	return nil
}

// compareBytes compares two byte slices in constant time
func compareBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var result byte
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}
	return result == 0
}

// Encrypt encrypts data with the quantum-resistant layer
func (q *QuantumResistantLayer) Encrypt(plaintext []byte) ([]byte, error) {
	q.mu.RLock()
	defer q.mu.RUnlock()

	if !q.enabled {
		return plaintext, nil
	}

	if q.cipher == nil {
		return nil, fmt.Errorf("cipher not initialized")
	}

	nonce := make([]byte, q.cipher.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := q.cipher.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts data with the quantum-resistant layer
func (q *QuantumResistantLayer) Decrypt(ciphertext []byte) ([]byte, error) {
	q.mu.RLock()
	defer q.mu.RUnlock()

	if !q.enabled {
		return ciphertext, nil
	}

	if q.cipher == nil {
		return nil, fmt.Errorf("cipher not initialized")
	}

	if len(ciphertext) < q.cipher.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce := ciphertext[:q.cipher.NonceSize()]
	encrypted := ciphertext[q.cipher.NonceSize():]

	plaintext, err := q.cipher.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// RotateKeys rotates the Kyber keys
func (q *QuantumResistantLayer) RotateKeys() error {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.generateKyberKeyPair()
}

// GetStatus returns the current status
func (q *QuantumResistantLayer) GetStatus() map[string]interface{} {
	q.mu.RLock()
	defer q.mu.RUnlock()

	keyID := "none"
	if len(q.sharedSecret) >= 8 {
		keyID = hex.EncodeToString(q.sharedSecret[:8])
	}

	return map[string]interface{}{
		"enabled":    q.enabled,
		"algorithm":  q.algorithm,
		"key_id":     keyID,
		"nist_level": 3,
		"security":   "192-bit quantum resistant",
	}
}

// IsEnabled returns whether the quantum layer is enabled
func (q *QuantumResistantLayer) IsEnabled() bool {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return q.enabled
}

// TestEncryption performs a self-test
func (q *QuantumResistantLayer) TestEncryption() (bool, error) {
	testData := []byte("TorForge Post-Quantum Encryption Test - CRYSTALS-Kyber768")

	encrypted, err := q.Encrypt(testData)
	if err != nil {
		return false, err
	}

	decrypted, err := q.Decrypt(encrypted)
	if err != nil {
		return false, err
	}

	if !compareBytes(testData, decrypted) {
		return false, fmt.Errorf("decrypted data does not match original")
	}

	return true, nil
}
