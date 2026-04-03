// Package field provides EncryptedField for encrypting a single database
// column and generating blind indexes for searching.
//
// # Overview
//
// An EncryptedField ties together:
//
//   - an engine.Engine instance (root key + backend),
//   - a table name and field name (for key scoping), and
//   - a set of blindindex.BlindIndex configurations.
//
// It is the single-column equivalent of paragonie/ciphersweet's
// EncryptedField.
//
// It supports encrypting a plaintext value, decrypting stored ciphertext,
// and computing deterministic blind index values for equality queries.
//
// Key Concepts / Features
//
//   - PrepareForStorage encrypts plaintext and computes all registered
//     blind indexes.
//   - Decrypt decrypts ciphertext produced by PrepareForStorage.
//   - GetBlindIndex computes a blind index value for a search query
//     without encryption.
//   - WithAAD binds additional authenticated data to ciphertexts.
//
// Example:
//
//	ef := field.New(eng, "users", "email").
//	    AddBlindIndex(blindindex.New("email_index",
//	        blindindex.WithBits(32),
//	        blindindex.WithTransform(transform.Lowercase{}),
//	    ))
//
//	// Encrypt + compute all blind indexes in one call.
//	ct, indexes, err := ef.PrepareForStorage("alice@example.com")
//	// → store ct in `email`, indexes["email_index"] in `email_index`
//
//	// Decrypt after SELECT.
//	plain, err := ef.Decrypt(ct)
//
//	// Compute the blind index for a search query (no encryption).
//	idx, err := ef.GetBlindIndex("alice@example.com", "email_index")
//	// → SELECT * FROM users WHERE email_index = ?  [idx]
//
//	_ = plain
//	_ = indexes
//	_ = idx
//
// Architecture / Design
//
// field.EncryptedField is a configuration object. It uses the Engine to:
// derive the encryption key for (tableName, fieldName) and compute blind
// indexes for each registered index name.
//
// # Security Notes
//
// CipherSweet encryption is authenticated. Ciphertexts should not be
// altered; decryption fails if authentication does not verify.
//
// Blind index values are deterministic. Treat them as sensitive because
// they enable equality checks against candidate plaintexts.
//
// # Compatibility
//
// With the NaCl backend, ciphertexts and blind index parameters are intended
// to be wire-compatible with Laravel CipherSweet implementations when
// table names, field names, and index configuration match.
//
// # Project Information
//
// Package name: field
// Project description: Field-level encryption and blind index generation.
// Key features:
//   - Encrypt + compute blind indexes for one column
//   - Decrypt stored ciphertexts
//   - Compute blind index values for search queries
//
// Example usage: field.New(eng, table, field).PrepareForStorage(...)
// Special notes: Use WithAAD when you need ciphertexts bound to extra
// per-row or per-tenant context.
package field
