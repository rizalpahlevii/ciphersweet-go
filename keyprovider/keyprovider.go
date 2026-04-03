package keyprovider

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// KeyProvider supplies the 32-byte root key to the engine.
type KeyProvider interface {
	// Key returns a fresh copy of the 32-byte root key.
	// Callers must zero the returned slice when done with it.
	Key() ([]byte, error)
}

// ── StringProvider ────────────────────────────────────────────────────────────

// StringProvider holds a key encoded as a 64-hex-character string (256 bits).
// This is the format emitted by `openssl rand -hex 32` and used by the
// CIPHERSWEET_KEY environment variable in Laravel deployments.
type StringProvider struct {
	raw [32]byte
}

// NewStringProvider decodes hexKey into a 32-byte key.
// hexKey must be exactly 64 hex characters (whitespace is trimmed).
func NewStringProvider(hexKey string) (*StringProvider, error) {
	b, err := hex.DecodeString(strings.TrimSpace(hexKey))
	if err != nil {
		return nil, fmt.Errorf("keyprovider: invalid hex key: %w", err)
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("keyprovider: key must be 32 bytes (64 hex chars), got %d bytes", len(b))
	}
	sp := &StringProvider{}
	copy(sp.raw[:], b)
	return sp, nil
}

// Key returns a copy of the raw 32-byte key.
func (s *StringProvider) Key() ([]byte, error) {
	out := make([]byte, 32)
	copy(out, s.raw[:])
	return out, nil
}

// ── EnvProvider ───────────────────────────────────────────────────────────────

// EnvProvider reads the hex-encoded key from an environment variable at call
// time (not at construction time), so a secret rotation in the process
// environment is picked up without restarting.
type EnvProvider struct {
	varName string
}

// NewEnvProvider creates an EnvProvider.
// If varName is empty it defaults to "CIPHERSWEET_KEY".
func NewEnvProvider(varName string) *EnvProvider {
	if varName == "" {
		varName = "CIPHERSWEET_KEY"
	}
	return &EnvProvider{varName: varName}
}

// Key reads and decodes the key from the environment variable.
func (e *EnvProvider) Key() ([]byte, error) {
	val := os.Getenv(e.varName)
	if val == "" {
		return nil, fmt.Errorf("keyprovider: env var %q is not set", e.varName)
	}
	sp, err := NewStringProvider(val)
	if err != nil {
		return nil, fmt.Errorf("keyprovider: env var %q: %w", e.varName, err)
	}
	return sp.Key()
}

// ── FileProvider ──────────────────────────────────────────────────────────────

// FileProvider reads the hex-encoded key from a file on every Key() call.
// The file must contain exactly 64 hex characters (a trailing newline is trimmed).
// This works well with Docker secrets (/run/secrets/) and Kubernetes secret mounts.
type FileProvider struct {
	path string
}

// NewFileProvider creates a FileProvider that reads from path.
func NewFileProvider(path string) *FileProvider {
	return &FileProvider{path: path}
}

// Key reads and decodes the key from the file.
func (f *FileProvider) Key() ([]byte, error) {
	data, err := os.ReadFile(f.path)
	if err != nil {
		return nil, fmt.Errorf("keyprovider: read %q: %w", f.path, err)
	}
	sp, err := NewStringProvider(string(data))
	if err != nil {
		return nil, fmt.Errorf("keyprovider: file %q: %w", f.path, err)
	}
	return sp.Key()
}

// ── RandomProvider ────────────────────────────────────────────────────────────

// RandomProvider generates a cryptographically random key once at construction
// and returns a copy of it on every Key() call.
//
// WARNING: the key is ephemeral — it is lost when the process exits.
// Use only for tests or transient data; never for data you need to decrypt later.
type RandomProvider struct {
	raw [32]byte
}

// NewRandomProvider generates a fresh random key. Returns an error if the OS
// CSPRNG is unavailable (this should never happen on a healthy system).
func NewRandomProvider() (*RandomProvider, error) {
	rp := &RandomProvider{}
	if _, err := io.ReadFull(rand.Reader, rp.raw[:]); err != nil {
		return nil, fmt.Errorf("keyprovider: generate random key: %w", err)
	}
	return rp, nil
}

// MustRandomProvider is like NewRandomProvider but panics on error.
// Convenient for test setup where error handling is noise.
func MustRandomProvider() *RandomProvider {
	rp, err := NewRandomProvider()
	if err != nil {
		panic(err)
	}
	return rp
}

// Key returns a copy of the random key.
func (r *RandomProvider) Key() ([]byte, error) {
	if r.raw == ([32]byte{}) {
		return nil, errors.New("keyprovider: random provider is zero-valued — use NewRandomProvider()")
	}
	out := make([]byte, 32)
	copy(out, r.raw[:])
	return out, nil
}

// HexString returns the key as a 64-character hex string.
// Useful for printing during test setup or initial key generation.
func (r *RandomProvider) HexString() string {
	return hex.EncodeToString(r.raw[:])
}
