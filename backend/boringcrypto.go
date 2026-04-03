package backend

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"

	"github.com/rizalpahlevii/ciphersweet-go/argon"
)

const (
	boringNonceSize = 12 // standard GCM nonce
	boringKeySize   = 32 // AES-256
	boringPrefix    = "boring:"
	gcmTagSize      = 16 // standard GCM authentication tag
)

// BoringCrypto is the AES-256-GCM backend for FIPS-140-constrained environments.
//
//   - Encryption      : AES-256-GCM (standard library crypto/cipher)
//   - Key derivation  : HKDF-SHA256
//   - Fast blind index: HMAC-SHA256
//   - Slow blind index: Argon2id
type BoringCrypto struct{}

// NewBoringCrypto returns a BoringCrypto backend.
func NewBoringCrypto() *BoringCrypto { return &BoringCrypto{} }

// ── Encrypt / Decrypt ──────────────────────────────────────────────────────────

func (b *BoringCrypto) Encrypt(plaintext, key, aad []byte) (string, error) {
	dk, err := b.deriveEncKey(key, aad)
	if err != nil {
		return "", fmt.Errorf("boring encrypt: %w", err)
	}

	gcm, err := newGCM(dk)
	if err != nil {
		return "", fmt.Errorf("boring encrypt: %w", err)
	}

	nonce := make([]byte, boringNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("boring encrypt: random nonce: %w", err)
	}

	// gcm.Seal appends [ct || tag] to nonce → final layout: [nonce || ct || tag]
	sealed := gcm.Seal(nonce, nonce, plaintext, aad)
	return boringPrefix + base64.RawURLEncoding.EncodeToString(sealed), nil
}

func (b *BoringCrypto) Decrypt(ciphertext string, key, aad []byte) ([]byte, error) {
	raw, err := boringStripPrefix(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("boring decrypt: %w", err)
	}
	if len(raw) < boringNonceSize+gcmTagSize {
		return nil, errors.New("boring decrypt: ciphertext too short")
	}

	dk, err := b.deriveEncKey(key, aad)
	if err != nil {
		return nil, fmt.Errorf("boring decrypt: %w", err)
	}

	gcm, err := newGCM(dk)
	if err != nil {
		return nil, fmt.Errorf("boring decrypt: %w", err)
	}

	nonce := raw[:boringNonceSize]
	pt, err := gcm.Open(nil, nonce, raw[boringNonceSize:], aad)
	if err != nil {
		return nil, errors.New("boring decrypt: authentication failed — wrong key or tampered data")
	}
	return pt, nil
}

// ── Key derivation ─────────────────────────────────────────────────────────────

func (b *BoringCrypto) DeriveFieldKey(rootKey []byte, tableName, fieldName string) ([]byte, error) {
	return b.hkdf(rootKey, "field|"+tableName+"|"+fieldName)
}

func (b *BoringCrypto) DeriveIndexKey(rootKey []byte, tableName, fieldName, indexName string) ([]byte, error) {
	return b.hkdf(rootKey, "index|"+tableName+"|"+fieldName+"|"+indexName)
}

// ── Blind indexes ──────────────────────────────────────────────────────────────

func (b *BoringCrypto) BlindIndexFast(plaintext, key []byte, outputBits int) (string, error) {
	if err := checkBits(outputBits); err != nil {
		return "", fmt.Errorf("boring BlindIndexFast: %w", err)
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(plaintext)
	return andMask(mac.Sum(nil), outputBits), nil
}

func (b *BoringCrypto) BlindIndexSlow(plaintext, key []byte, outputBits int, cfg *argon.Config) (string, error) {
	if err := checkBits(outputBits); err != nil {
		return "", fmt.Errorf("boring BlindIndexSlow: %w", err)
	}
	c := argon.Resolved(cfg)
	outBytes := (outputBits + 7) / 8
	//nolint:gosec // outBytes is bounded safely
	hash := argon2.IDKey(plaintext, key, c.TimeCost, c.MemoryCost, c.Parallelism, uint32(outBytes))
	return andMask(hash, outputBits), nil
}

// ── Internal helpers ───────────────────────────────────────────────────────────

// deriveEncKey mixes the field key with aad via HKDF, binding the aad to the
// key material — not only to the GCM authentication tag.
func (b *BoringCrypto) deriveEncKey(fieldKey, aad []byte) ([]byte, error) {
	info := "encrypt"
	if len(aad) > 0 {
		info += "|" + string(aad)
	}
	return b.hkdf(fieldKey, info)
}

func (b *BoringCrypto) hkdf(secret []byte, info string) ([]byte, error) {
	r := hkdf.New(sha256.New, secret, nil, []byte(info))
	out := make([]byte, boringKeySize)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, fmt.Errorf("hkdf: %w", err)
	}
	return out, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cipher.NewGCM: %w", err)
	}
	return gcm, nil
}

func boringStripPrefix(ct string) ([]byte, error) {
	if len(ct) <= len(boringPrefix) || ct[:len(boringPrefix)] != boringPrefix {
		return nil, errors.New("missing or invalid 'boring:' prefix")
	}
	// Accept both raw base64url (no padding) and padded base64url (trailing =).
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(ct[len(boringPrefix):], "="))
}
