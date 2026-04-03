// Package blindindex provides configuration for searchable blind indexes.
//
// # Overview
//
// A BlindIndex specifies how a plaintext value is transformed and hashed
// into a deterministic string that can be used in equality queries.
//
// Key Concepts / Features
//
//   - Deterministic output for a given plaintext and configuration.
//   - Optional transformations (for example, case-folding) applied before
//     hashing.
//   - Configurable output width in bits.
//   - Two hashing modes:
//   - slow (Argon2id, default) and
//   - fast (BLAKE2b).
//
// Example:
//
//	ef := field.New(eng, "users", "email").
//	    AddBlindIndex(blindindex.New("email_index",
//	        blindindex.WithBits(256),
//	        blindindex.WithFast(),
//	        blindindex.WithTransform(transform.Lowercase{}),
//	    ))
//
//	ct, indexes, err := ef.PrepareForStorage("Alice@Example.com")
//	_ = ct
//	_ = indexes
//	_ = err
//
//	// Search value for an exact-match query:
//	idx, err := ef.GetBlindIndex("alice@example.com", "email_index")
//	_ = idx
//	_ = err
//
// Architecture / Design
//
// BlindIndex.Apply applies configured transformations. Computing the
// blind index value itself is performed by the Engine as part of field
// or row encryption.
//
// # Security Notes
//
// Blind index values are deterministic. Treat them as sensitive because
// they can be used for equality checks against candidate plaintexts.
//
// # Compatibility
//
// Defaults are intended to match the PHP CipherSweet BlindIndex behavior:
// PHP's BlindIndex constructor defaults to fastHash=false (Argon2id). This
// Go implementation matches that default: New() creates an Argon2id-based
// (slow) index by default. Use WithFast() to opt into BLAKE2b for
// performance.
//
//	// Default: Argon2id (matches PHP new BlindIndex('email_index'))
//	blindindex.New("email_index")
//
//	// Explicit fast: BLAKE2b (matches PHP new BlindIndex('email_index', [], 256, true))
//	blindindex.New("email_index", blindindex.WithFast())
//
//	// With transforms and custom bit width:
//	blindindex.New("email_index",
//	    blindindex.WithBits(32),
//	    blindindex.WithTransform(transform.Lowercase{}),
//	)
//
// # Project Information
//
// Package name: blindindex
// Project description: Blind index configuration and transformation helpers.
// Key features:
//   - BlindIndex configuration (bits, fast/slow, transforms)
//   - Apply transformations in order
//
// Example usage: field.New(eng, table, field).AddBlindIndex(blindindex.New(...))
// Special notes: Determinism supports equality search on ciphertext columns.
package blindindex
