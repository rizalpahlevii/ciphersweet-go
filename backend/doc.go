// Package backend provides the cryptographic primitive layer used by Engine.
//
// # Overview
//
// A backend.Backend implementation provides the low-level operations needed
// by the ciphersweet-go Engine:
//
//   - Encrypt / decrypt field ciphertext.
//   - Derive per-field and per-index keys.
//   - Compute blind index values (deterministic, equality-searchable).
//
// Key Concepts / Features
//
//   - Pluggable: Engine delegates cryptographic work to the Backend.
//   - Key isolation: derived keys are scoped to table/field/index names.
//   - Authenticated encryption: ciphertexts include an authentication tag.
//   - Wire-safe representation: Encrypt returns a base64url string suitable
//     for TEXT columns.
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
//	// NaCl backend (ModernCrypto-compatible): XChaCha20-Poly1305 +
//	// deterministic blind indexes.
//	eng, err := engine.New(backend.NewNaCl(), kp)
//	if err != nil {
//	    panic(err)
//	}
//
// Architecture / Design
//
// Backend is an interface. It separates key derivation and cryptographic
// primitives from the higher-level Engine that wires those primitives together.
//
// # Security Notes
//
// Field encryption is authenticated. Decrypt fails if the ciphertext is
// modified, or if the wrong root key is used.
//
// Blind index values are deterministic. They should be treated as sensitive
// because they support equality checks on the corresponding plaintext.
//
// # Compatibility
//
// The NaCl backend is intended to be wire-compatible with Laravel CipherSweet
// implementations (magentron/ciphersweet-for-laravel and
// bjornvoesten/ciphersweet) when the same root key, table name, field name,
// and index configuration are used.
//
// # Project Information
//
// Package name: backend
// Project description: Cryptographic backends used by the CipherSweet
// engine.
// Key features:
//   - Field and index encryption key derivation
//   - Blind index computation (fast and slow)
//   - Backend pluggability via backend.Backend
//
// Example usage: engine.New(backend.NewNaCl(), keyprovider.NewEnvProvider(...))
// Special notes: Decrypt returns an error on authentication failures.
package backend
