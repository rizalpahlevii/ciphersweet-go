// Package engine provides field encryption and blind index computation for
// CipherSweet.
//
// # Overview
//
// The Engine wires a root key provider to a cryptographic backend. It derives
// per-field and per-index keys scoped to a table name, field name, and index
// name, then delegates all cryptographic operations (including key
// derivation) to the backend. The backend is responsible for implementing
// the key hierarchy as defined by paragonie/ciphersweet.
//
// Key Features
//
//   - Authenticated encryption for field ciphertext.
//   - Deterministic blind index values for exact-match searching.
//   - Pluggable cryptographic backends.
//   - Concurrency-safe operation after construction.
//
// Example:
//
//	kp, err := keyprovider.NewStringProvider(
//	    "84d269301777265c1915f44f9f9f36a34323fed7c6e0069bdbf03ea37ecb0880",
//	)
//	if err != nil {
//	    panic(err)
//	}
//
//	eng, err := engine.New(backend.NewNaCl(), kp)
//	if err != nil {
//	    panic(err)
//	}
//
//	ef := field.New(eng, "users", "email").
//	    AddBlindIndex(blindindex.New("email_index"))
//
//	ct, indexes, err := ef.PrepareForStorage("alice@example.com")
//	if err != nil {
//	    panic(err)
//	}
//
//	plaintext, err := ef.Decrypt(ct)
//	if err != nil {
//	    panic(err)
//	}
//
//	// Search value for an exact-match query:
//	idx, err := ef.GetBlindIndex("alice@example.com", "email_index")
//	if err != nil {
//	    panic(err)
//	}
//
//	_ = indexes
//	_ = plaintext
//	_ = idx
//
// Architecture / Design
//
// Engine is a thin coordinator. It uses a backend.Backend implementation to:
//
//   - derive an encryption key for (tableName, fieldName), then encrypt and
//     decrypt values; and
//   - derive an index key for (tableName, fieldName, indexName), then compute
//     blind indexes using either a fast or slow backend algorithm.
//
// # Security Notes
//
// CipherSweet encryption is authenticated. If the ciphertext is tampered with,
// or if an incorrect root key is supplied, decryption fails.
//
// Blind index values are deterministic for a given plaintext and index
// configuration, so they should be treated as sensitive.
//
// # Compatibility
//
// With the NaCl backend (backend.NewNaCl, also referred to as ModernCrypto /
// "modern"), ciphertexts and blind index parameters are intended to be wire-
// compatible with Laravel CipherSweet implementations
// (magentron/ciphersweet-for-laravel and bjornvoesten/ciphersweet).
//
// # Project Information
//
// Package name: engine
// Project description: Wires the CipherSweet root key to a backend and provides
// field encryption and blind index computation primitives.
// Key features:
//   - Field key derivation and encryption
//   - Blind index derivation and computation
//   - Backend pluggability via backend.Backend
//
// Example usage: field.New(eng, table, field).AddBlindIndex(...)
// Special notes: Deterministic blind index values can be used to test for
// equality of plaintexts.
package engine
