package backend

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"

	"github.com/rizalpahlevii/ciphersweet-go/argon"
)

const (
	naclNonceSize = 24 // XChaCha20 nonce = 192 bits
	naclKeySize   = 32
	naclPrefix    = "nacl:"
	maxIndexBits  = 512
)

// domain separation constants — match PHP Constants::DS_FENC and DS_BIDX
var (
	dsFenc = bytes32(0xB4) // field encryption key prefix
	dsBidx = bytes32(0x7E) // blind index key prefix
)

func bytes32(b byte) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = b
	}
	return out
}

// NaCl matches PHP paragonie/ciphersweet ModernCrypto exactly.
//
// Key derivation : hash_hkdf('sha384', key, 32, info, salt)
//   - field key  : salt=tableName, info=DS_FENC+fieldName
//   - index key  : salt=tableName, info=DS_BIDX+fieldName  (root)
//     then: salt=tableName, info=DS_BIDX+fieldName+indexName (per-index)
//
// Encryption     : XChaCha20-Poly1305, AAD = nonce + caller_aad
// Fast index     : BLAKE2b keyed hash (crypto_generichash)
// Slow index     : Argon2id, salt = blake2b(key, 16 bytes)
type NaCl struct{}

// NewNaCl returns a NaCl backend compatible with PHP paragonie/ciphersweet.
func NewNaCl() *NaCl { return &NaCl{} }

// ── Encrypt / Decrypt ──────────────────────────────────────────────────────────

func (n *NaCl) Encrypt(plaintext, key, aad []byte) (string, error) {
	nonce := make([]byte, naclNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("nacl encrypt: random nonce: %w", err)
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return "", fmt.Errorf("nacl encrypt: %w", err)
	}

	// PHP: additional_data = $nonce . $aad
	// Use explicit allocation to avoid append corrupting the nonce slice.
	ad := make([]byte, len(nonce)+len(aad))
	copy(ad, nonce)
	copy(ad[len(nonce):], aad)

	ct := aead.Seal(nil, nonce, plaintext, ad)

	payload := make([]byte, len(nonce)+len(ct))
	copy(payload, nonce)
	copy(payload[len(nonce):], ct)
	return naclPrefix + base64.RawURLEncoding.EncodeToString(payload), nil
}

func (n *NaCl) Decrypt(ciphertext string, key, aad []byte) ([]byte, error) {
	raw, err := naclStripPrefix(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("nacl decrypt: %w", err)
	}
	if len(raw) < naclNonceSize+16 {
		return nil, errors.New("nacl decrypt: ciphertext too short")
	}

	// Copy nonce out of raw to avoid append aliasing the ciphertext bytes.
	nonce := make([]byte, naclNonceSize)
	copy(nonce, raw[:naclNonceSize])
	encrypted := raw[naclNonceSize:]

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("nacl decrypt: %w", err)
	}

	// PHP: additional_data = $nonce . $aad
	ad := make([]byte, len(nonce)+len(aad))
	copy(ad, nonce)
	copy(ad[len(nonce):], aad)
	pt, err := aead.Open(nil, nonce, encrypted, ad)
	if err != nil {
		return nil, errors.New("nacl decrypt: authentication failed — wrong key or tampered data")
	}
	return pt, nil
}

// ── Key derivation ─────────────────────────────────────────────────────────────
// Matches PHP Util::HKDF which calls:
//   hash_hkdf('sha384', $key->getRawKey(), 32, $info, $salt)
//
// Field key : salt=tableName, info=DS_FENC(0xB4×32) + fieldName
// Index key : salt=tableName, info=DS_BIDX(0x7E×32) + fieldName  (root)
//             then per-index: no further derivation needed for ModernCrypto
//             (getBlindIndexRootKey returns the key used directly for hashing)

func (n *NaCl) DeriveFieldKey(rootKey []byte, tableName, fieldName string) ([]byte, error) {
	// hash_hkdf('sha384', rootKey, 32, DS_FENC+fieldName, tableName)
	// Use explicit allocation — append on a package var reuses its backing array.
	info := make([]byte, len(dsFenc)+len(fieldName))
	copy(info, dsFenc)
	copy(info[len(dsFenc):], fieldName)
	return hkdfSHA384(rootKey, []byte(tableName), info)
}

func (n *NaCl) DeriveIndexKey(rootKey []byte, tableName, fieldName, indexName string) ([]byte, error) {
	// Step 1: index root key = HKDF-SHA384(rootKey, salt=tableName, info=DS_BIDX+fieldName)
	// Matches PHP: getBlindIndexRootKey → Util::HKDF(key, tableName, DS_BIDX+fieldName)
	// Use explicit allocation — append on a package var reuses its backing array.
	info := make([]byte, len(dsBidx)+len(fieldName))
	copy(info, dsBidx)
	copy(info[len(dsBidx):], fieldName)
	indexRootKey, err := hkdfSHA384(rootKey, []byte(tableName), info)
	if err != nil {
		return nil, err
	}

	// Step 2: per-index sub-key = HMAC-SHA256(msg=pack(tableName,fieldName,indexName), key=indexRootKey)
	// Matches PHP: getBlindIndexRaw → hash_hmac('sha256', Util::pack([table,field,index]), rootKey)
	mac := hmacSHA256(indexRootKey, pack(tableName, fieldName, indexName))
	return mac, nil
}

// hkdfSHA384 implements PHP's hash_hkdf('sha384', key, 32, info, salt).
// Go's hkdf.New takes (hash, secret, salt, info) — same parameters, different order.
func hkdfSHA384(key, salt, info []byte) ([]byte, error) {
	r := hkdf.New(sha512.New384, key, salt, info)
	out := make([]byte, naclKeySize)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, fmt.Errorf("hkdf-sha384: %w", err)
	}
	return out, nil
}

// ── Blind indexes ──────────────────────────────────────────────────────────────

// BlindIndexFast matches PHP ModernCrypto::blindIndexFast:
//
//	$hash = crypto_generichash($plaintext, $key->getRawKey(), $hashLength)
//	return Util::andMask($hash, $bitLength)
func (n *NaCl) BlindIndexFast(plaintext, key []byte, outputBits int) (string, error) {
	if err := checkBits(outputBits); err != nil {
		return "", fmt.Errorf("nacl BlindIndexFast: %w", err)
	}
	hashLen := 32
	if outputBits > 256 {
		hashLen = (outputBits + 7) / 8
	}
	h, err := blake2b.New(hashLen, key)
	if err != nil {
		return "", fmt.Errorf("nacl BlindIndexFast: blake2b: %w", err)
	}
	h.Write(plaintext)
	return andMask(h.Sum(nil), outputBits), nil
}

// BlindIndexSlow matches PHP ModernCrypto::blindIndexSlow:
//
//	$salt = crypto_generichash($key->getRawKey(), '', 16)
//	$hash = sodium_crypto_pwhash($len, $plaintext, $salt, $ops, $mem, ARGON2ID)
func (n *NaCl) BlindIndexSlow(plaintext, key []byte, outputBits int, cfg *argon.Config) (string, error) {
	if err := checkBits(outputBits); err != nil {
		return "", fmt.Errorf("nacl BlindIndexSlow: %w", err)
	}
	c := argon.Resolved(cfg)
	outBytes := (outputBits + 7) / 8
	if outBytes < 16 {
		outBytes = 16
	}
	// PHP: salt = crypto_generichash($key->getRawKey(), '', 16)
	h, err := blake2b.New(16, nil) // unkeyed, 16-byte output
	if err != nil {
		return "", fmt.Errorf("nacl BlindIndexSlow: %w", err)
	}
	h.Write(key)
	salt := h.Sum(nil)

	//nolint:gosec // outBytes is strictly validated and safe
	hash := argon2.IDKey(plaintext, salt, c.TimeCost, c.MemoryCost, c.Parallelism, uint32(outBytes))
	return andMask(hash, outputBits), nil
}

// ── Internal helpers ───────────────────────────────────────────────────────────

func naclStripPrefix(ct string) ([]byte, error) {
	if len(ct) <= len(naclPrefix) || ct[:len(naclPrefix)] != naclPrefix {
		return nil, errors.New("missing or invalid 'nacl:' prefix")
	}
	// Accept both raw base64url (no padding) and padded (trailing =).
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(ct[len(naclPrefix):], "="))
}

// ── Shared helpers ────────────────────────────────────────────────────────────

func checkBits(outputBits int) error {
	if outputBits < 1 || outputBits > maxIndexBits {
		return fmt.Errorf("outputBits %d out of range [1, %d]", outputBits, maxIndexBits)
	}
	return nil
}

// andMask matches PHP Util::andMask + Hex::encode.
// PHP always returns lowercase hex for all bit widths via Hex::encode(andMask(...)).
// The bitmask zeroes trailing bits in the last byte, then the result is hex-encoded directly.
func andMask(data []byte, outputBits int) string {
	outputBytes := (outputBits + 7) / 8
	out := make([]byte, outputBytes)
	copy(out, data[:outputBytes])
	// Zero trailing bits in the last byte.
	if rem := outputBits % 8; rem != 0 {
		out[outputBytes-1] &= byte(0xFF) << (8 - rem)
	}
	// PHP: return Hex::encode($masked) — plain lowercase hex for all sizes.
	return fmt.Sprintf("%x", out)
}

// hmacSHA256 computes HMAC-SHA256(key, msg).
func hmacSHA256(key, msg []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(msg)
	return mac.Sum(nil)
}

// pack encodes strings exactly as PHP Util::pack:
//
//	[LE uint32: count] [LE uint64: len(s)] [s bytes] ...
//
// e.g. pack("users","ssn","ssn_full_index") matches PHP Util::pack([$table,$field,$index])
func pack(parts ...string) []byte {
	out := make([]byte, 4)
	//nolint:gosec // parts length is safely bounded by pack implementation
	binary.LittleEndian.PutUint32(out, uint32(len(parts)))
	for _, p := range parts {
		lb := make([]byte, 8)
		binary.LittleEndian.PutUint64(lb, uint64(len(p)))
		out = append(out, lb...)
		out = append(out, p...)
	}
	return out
}
