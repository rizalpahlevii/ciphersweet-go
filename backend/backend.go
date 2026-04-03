package backend

import "github.com/rizalpahlevii/ciphersweet-go/argon"

// Backend is the cryptographic primitive layer used by the engine.
type Backend interface {
	// Encrypt encrypts plaintext with key.  aad (additional authenticated data)
	// is bound to the ciphertext MAC; pass nil if unused.
	// Returns a prefixed, base64url-encoded string safe to store in TEXT columns.
	Encrypt(plaintext, key, aad []byte) (string, error)

	// Decrypt verifies and decrypts a ciphertext produced by Encrypt.
	// aad must match exactly what was supplied during Encrypt.
	Decrypt(ciphertext string, key, aad []byte) ([]byte, error)

	// DeriveFieldKey derives a unique 32-byte encryption key for one column.
	// Scoped to tableName + fieldName via HKDF so every column is independent.
	DeriveFieldKey(rootKey []byte, tableName, fieldName string) ([]byte, error)

	// DeriveIndexKey derives a unique 32-byte key for one blind index.
	// Scoped to tableName + fieldName + indexName.
	DeriveIndexKey(rootKey []byte, tableName, fieldName, indexName string) ([]byte, error)

	// BlindIndexFast computes an HMAC-SHA256 blind index truncated to outputBits.
	// outputBits ∈ [1, 512].
	BlindIndexFast(plaintext, key []byte, outputBits int) (string, error)

	// BlindIndexSlow computes an Argon2id blind index truncated to outputBits.
	// cfg == nil uses argon.DefaultConfig().
	BlindIndexSlow(plaintext, key []byte, outputBits int, cfg *argon.Config) (string, error)
}
