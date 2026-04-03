package engine

import (
	"fmt"
	"sync"

	"github.com/rizalpahlevii/ciphersweet-go/argon"
	"github.com/rizalpahlevii/ciphersweet-go/backend"
	"github.com/rizalpahlevii/ciphersweet-go/keyprovider"
)

// Engine holds the root key and wires it to a Backend.
// Safe for concurrent use after construction.
type Engine struct {
	b        backend.Backend
	once     sync.Once
	rootKey  [32]byte
	keyErr   error
	provider keyprovider.KeyProvider
}

// New creates an Engine, eagerly fetching and caching the root key.
func New(b backend.Backend, kp keyprovider.KeyProvider) (*Engine, error) {
	e := &Engine{b: b, provider: kp}
	if err := e.initKey(); err != nil {
		return nil, err
	}
	return e, nil
}

// MustNew is like New but panics on error.
func MustNew(b backend.Backend, kp keyprovider.KeyProvider) *Engine {
	e, err := New(b, kp)
	if err != nil {
		panic(fmt.Sprintf("ciphersweet engine: %v", err))
	}
	return e
}

// Backend returns the underlying Backend.
func (e *Engine) Backend() backend.Backend { return e.b }

// ── Field encryption ──────────────────────────────────────────────────────────

// EncryptField derives the field key then encrypts plaintext.
// The key derivation follows the paragonie key hierarchy exactly.
func (e *Engine) EncryptField(plaintext []byte, tableName, fieldName string, aad []byte) (string, error) {
	fk, err := e.b.DeriveFieldKey(e.root(), tableName, fieldName)
	if err != nil {
		return "", fmt.Errorf("engine: derive field key [%s.%s]: %w", tableName, fieldName, err)
	}
	ct, err := e.b.Encrypt(plaintext, fk, aad)
	if err != nil {
		return "", fmt.Errorf("engine: encrypt [%s.%s]: %w", tableName, fieldName, err)
	}
	return ct, nil
}

// DecryptField derives the field key then decrypts ciphertext.
func (e *Engine) DecryptField(ciphertext, tableName, fieldName string, aad []byte) ([]byte, error) {
	fk, err := e.b.DeriveFieldKey(e.root(), tableName, fieldName)
	if err != nil {
		return nil, fmt.Errorf("engine: derive field key [%s.%s]: %w", tableName, fieldName, err)
	}
	pt, err := e.b.Decrypt(ciphertext, fk, aad)
	if err != nil {
		return nil, fmt.Errorf("engine: decrypt [%s.%s]: %w", tableName, fieldName, err)
	}
	return pt, nil
}

// ── Blind indexes ─────────────────────────────────────────────────────────────

// BlindIndexFast derives the index key then computes a BLAKE2b blind index.
func (e *Engine) BlindIndexFast(
	transformedValue string,
	tableName, fieldName, indexName string,
	outputBits int,
) (string, error) {
	ik, err := e.b.DeriveIndexKey(e.root(), tableName, fieldName, indexName)
	if err != nil {
		return "", fmt.Errorf("engine: derive index key [%s.%s/%s]: %w", tableName, fieldName, indexName, err)
	}
	v, err := e.b.BlindIndexFast([]byte(transformedValue), ik, outputBits)
	if err != nil {
		return "", fmt.Errorf("engine: fast index [%s.%s/%s]: %w", tableName, fieldName, indexName, err)
	}
	return v, nil
}

// BlindIndexSlow derives the index key then computes an Argon2id blind index.
func (e *Engine) BlindIndexSlow(
	transformedValue string,
	tableName, fieldName, indexName string,
	outputBits int,
	cfg *argon.Config,
) (string, error) {
	ik, err := e.b.DeriveIndexKey(e.root(), tableName, fieldName, indexName)
	if err != nil {
		return "", fmt.Errorf("engine: derive index key [%s.%s/%s]: %w", tableName, fieldName, indexName, err)
	}
	v, err := e.b.BlindIndexSlow([]byte(transformedValue), ik, outputBits, cfg)
	if err != nil {
		return "", fmt.Errorf("engine: slow index [%s.%s/%s]: %w", tableName, fieldName, indexName, err)
	}
	return v, nil
}

// ── Internal ──────────────────────────────────────────────────────────────────

func (e *Engine) initKey() error {
	e.once.Do(func() {
		k, err := e.provider.Key()
		if err != nil {
			e.keyErr = fmt.Errorf("engine: key provider: %w", err)
			return
		}
		if len(k) != 32 {
			e.keyErr = fmt.Errorf("engine: key must be 32 bytes, got %d", len(k))
			return
		}
		copy(e.rootKey[:], k)
		for i := range k {
			k[i] = 0
		}
	})
	return e.keyErr
}

func (e *Engine) root() []byte { return e.rootKey[:] }
