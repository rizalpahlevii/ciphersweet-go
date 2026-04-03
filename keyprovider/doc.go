// Package keyprovider provides the root symmetric key to the CipherSweet
// engine.
//
// # Overview
//
// The CipherSweet engine requires a single 32-byte root key. This package
// provides KeyProvider implementations to obtain that key from different
// sources.
//
// Key Concepts / Features
//
//   - KeyProvider returns a fresh 32-byte key copy on every call.
//   - StringProvider accepts the 64-hex-character format used by Laravel.
//   - EnvProvider reads the key from an environment variable at call time.
//   - FileProvider reads the key from a file on every call (for secrets).
//   - RandomProvider generates an ephemeral random key (tests only).
//
// Example:
//
//	kp := keyprovider.NewEnvProvider("CIPHERSWEET_KEY")
//	eng, err := engine.New(backend.NewNaCl(), kp)
//	if err != nil {
//	    panic(err)
//	}
//
// Architecture / Design
//
// KeyProvider is an abstraction over key storage and retrieval. The engine
// calls Key() during construction to obtain the root key material.
//
// # Security Notes
//
// RandomProvider should never be used for production because it generates an
// ephemeral key.
//
// # Project Information
//
// Package name: keyprovider
// Project description: Root key providers for ciphersweet-go.
// Key features:
//   - Env / file / literal key loading
//   - 32-byte root key validation
//
// Example usage: engine.New(backend.NewNaCl(), keyprovider.NewEnvProvider(...))
// Special notes: StringProvider expects exactly 64 hex chars (32 bytes).
package keyprovider
