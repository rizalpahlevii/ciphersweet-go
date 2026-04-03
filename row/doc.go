// Package row provides EncryptedRow for encrypting multiple columns of the
// same database row and computing blind indexes.
//
// # Overview
//
// EncryptedRow encrypts several plaintext fields using a shared engine and
// computes all their registered blind indexes in one pass. It also supports
// decrypting stored ciphertext values and computing blind index values for
// equality queries.
//
// It is the multi-column equivalent of paragonie/ciphersweet's EncryptedRow
// class.
//
// Key Concepts / Features
//
//   - AddField registers required plaintext fields.
//   - AddOptionalTextField stores empty strings without encryption.
//   - PrepareForStorage encrypts all fields present in a map and computes
//     all blind indexes.
//   - DecryptRow decrypts ciphertext back into plaintext.
//   - GetBlindIndex computes a deterministic blind index value for search.
//   - WithStrict returns an error on missing required fields.
//
// Example:
//
//	er := row.New(eng, "users").
//	    AddField("email").
//	    AddField("phone").
//	    AddField("ssn").
//	    AddOptionalTextField("middle_name").
//	    AddBlindIndex("email", blindindex.New("email_index",
//	        blindindex.WithBits(32),
//	        blindindex.WithTransform(transform.Lowercase{}),
//	    )).
//	    AddBlindIndex("ssn", blindindex.New("ssn_last_four_index",
//	        blindindex.WithBits(16),
//	        blindindex.WithTransform(transform.LastFourDigits{}),
//	    ))
//
//	enc, indexes, err := er.PrepareForStorage(row.RowData{
//	    "email": "alice@example.com",
//	    "phone": "+1-555-867-5309",
//	    "ssn":   "123-45-6789",
//	})
//	if err != nil {
//	    panic(err)
//	}
//
//	plain, err := er.DecryptRow(enc)
//	if err != nil {
//	    panic(err)
//	}
//
//	// Search:
//	idx, err := er.GetBlindIndex("email", "alice@example.com", "email_index")
//	// → SELECT * FROM users WHERE email_index = ?  [idx]
//
//	_ = plain
//	_ = indexes
//	_ = idx
//
// Architecture / Design
//
// Row-level operations are built on top of Engine field operations:
// encryption keys are derived per (table, field) pair and blind index keys
// are derived per (table, field, indexName) pair.
//
// # Security Notes
//
// Field ciphertext uses authenticated encryption. DecryptRow fails if any
// ciphertext is modified or if the root key is incorrect.
//
// Blind index values are deterministic. Treat index columns as sensitive.
//
// # Compatibility
//
// With the NaCl backend, ciphertexts and blind index values are intended to
// match Laravel CipherSweet when table names, field names, and index
// configuration match.
//
// # Project Information
//
// Package name: row
// Project description: Multi-column encryption and blind index generation.
// Key features:
//   - Encrypt multiple fields in one call
//   - Compute multiple blind indexes simultaneously
//   - Decrypt back into plaintext
//
// Example usage: row.New(eng, table).AddField(...).PrepareForStorage(...)
// Special notes: WithStrict enables stricter validation for missing fields.
package row
