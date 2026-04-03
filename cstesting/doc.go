// Package cstesting provides test helpers for ciphersweet-go.
//
// # Overview
//
// The helpers in this package provide reproducible test engines and
// assertion functions for encryption and blind index behavior.
//
// Key Concepts / Features
//
//   - NewEngine wires a NaCl Engine with a fixed deterministic key.
//   - Pre-built EncryptedField and EncryptedRow configurations for common
//     test schemas.
//   - Assertion helpers for encryption round-trips and blind index
//     determinism/probabilistic properties.
//
// Example:
//
//	import cstesting "github.com/rizalpahlevii/ciphersweet-go/cstesting"
//
//	func TestEmail(t *testing.T) {
//	    ef := cstesting.EmailField(t)
//	    ct, indexes, err := ef.PrepareForStorage("alice@example.com")
//	    cstesting.NoError(t, err)
//	    cstesting.AssertDecrypts(t, ef, ct, "alice@example.com")
//	    cstesting.AssertIndexSearchable(t, ef, "alice@example.com", "email_index", indexes)
//	    cstesting.AssertCiphertextDiffers(t, ef, "alice@example.com") // probabilistic
//	    cstesting.AssertIndexStable(t, ef, "alice@example.com", "email_index") // deterministic
//	}
//
// Architecture / Design
//
// cstesting provides convenience factories for engines and configuration
// objects. It intentionally avoids external configuration (for example, it
// does not read environment variables).
//
// # Security Notes
//
// A deterministic fixedHexKey is used for test reproducibility. It must
// never be used in production.
//
// # Compatibility
//
// The test helpers validate properties (encryption round-trip, blind index
// determinism) that are expected to hold across backends.
//
// # Project Information
//
// Package name: cstesting
// Project description: Test helpers and assertions for ciphersweet-go.
// Key features:
//   - Fixed-key engine factories for reproducible tests
//   - Prebuilt EncryptedField / EncryptedRow helpers
//   - Assertion helpers for encryption and blind indexes
//
// Example usage: ef := cstesting.EmailField(t)
// Special notes: The fixed test key is not safe for production use.
package cstesting
