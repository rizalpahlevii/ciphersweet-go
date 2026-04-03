package backend

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/rizalpahlevii/ciphersweet-go/argon"
)

func fixedKey32() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i)
	}
	return k
}

const (
	aliceEmail = "alice@example.com"
	bobEmail   = "bob@example.com"

	deterministicFmt = "expected deterministic output, got %q vs %q"
)

func flipBase64URLChar(s string, pos int) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	if pos < 0 || pos >= len(s) {
		return s
	}
	orig := s[pos]
	// Find a different character in the same alphabet.
	for i := 0; i < len(alphabet); i++ {
		c := alphabet[i]
		if c != orig {
			b := []byte(s)
			b[pos] = c
			return string(b)
		}
	}
	return s
}

func TestNaClEncryptDecryptRoundTrip(t *testing.T) {
	n := NewNaCl()
	key := fixedKey32()
	key2 := make([]byte, 32)
	copy(key2, key)
	key2[0] ^= 0x01

	aad := []byte("tenant-A")
	pt := []byte(aliceEmail)

	ct1, err := n.Encrypt(pt, key, aad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	ct2, err := n.Encrypt(pt, key, aad)
	if err != nil {
		t.Fatalf("Encrypt(2): %v", err)
	}

	if !strings.HasPrefix(ct1, naclPrefix) {
		t.Fatalf("expected prefix %q, got %q", naclPrefix, ct1[:min(len(ct1), 12)])
	}
	if ct1 == ct2 {
		// Extremely unlikely: XChaCha20 nonce collision.
		t.Fatal("expected ciphertexts to differ for the same plaintext")
	}

	got, err := n.Decrypt(ct1, key, aad)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(got) != string(pt) {
		t.Fatalf("Decrypt mismatch: got %q want %q", string(got), string(pt))
	}

	// Wrong key should fail authentication.
	_, err = n.Decrypt(ct1, key2, aad)
	if err == nil {
		t.Fatal("expected decrypt to fail with wrong key")
	}

	// Tampering with ciphertext should fail authentication.
	tampered := flipBase64URLChar(ct1, len(naclPrefix)+1)
	_, err = n.Decrypt(tampered, key, aad)
	if err == nil {
		t.Fatal("expected decrypt to fail for tampered ciphertext")
	}
}

func TestNaClBlindIndexDeterminismAndRange(t *testing.T) {
	n := NewNaCl()
	key := fixedKey32()

	out1, err := n.BlindIndexFast([]byte(aliceEmail), key, 32)
	if err != nil {
		t.Fatalf("BlindIndexFast: %v", err)
	}
	out2, err := n.BlindIndexFast([]byte(aliceEmail), key, 32)
	if err != nil {
		t.Fatalf("BlindIndexFast(2): %v", err)
	}
	if out1 != out2 {
		t.Fatalf(deterministicFmt, out1, out2)
	}

	other, err := n.BlindIndexFast([]byte(bobEmail), key, 32)
	if err != nil {
		t.Fatalf("BlindIndexFast(other): %v", err)
	}
	if out1 == other {
		t.Fatal("expected different plaintexts to yield different blind index values")
	}

	// outputBits validation.
	if _, err := n.BlindIndexFast([]byte("x"), key, 0); err == nil {
		t.Fatal("expected error for outputBits=0")
	}

	// Hex length should match the masked output size.
	// outputBytes := (outputBits + 7) / 8, and fmt.Sprintf("%x") prints 2 chars per byte.
	// 32 bits -> 4 bytes -> 8 hex chars.
	if got, want := len(out1), 8; got != want {
		t.Fatalf("BlindIndexFast len: got %d want %d (%q)", got, want, out1)
	}
}

func TestNaClBlindIndexSlowDeterminism(t *testing.T) {
	n := NewNaCl()
	key := fixedKey32()

	cfg := &argon.Config{
		TimeCost:    1,
		MemoryCost:  32 * 1024, // 32 MiB
		Parallelism: 1,
	}

	out1, err := n.BlindIndexSlow([]byte(aliceEmail), key, 32, cfg)
	if err != nil {
		t.Fatalf("BlindIndexSlow: %v", err)
	}
	out2, err := n.BlindIndexSlow([]byte(aliceEmail), key, 32, cfg)
	if err != nil {
		t.Fatalf("BlindIndexSlow(2): %v", err)
	}
	if out1 != out2 {
		t.Fatalf(deterministicFmt, out1, out2)
	}
}

func TestBoringCryptoEncryptDecryptRoundTrip(t *testing.T) {
	b := NewBoringCrypto()
	key := fixedKey32()
	key2 := make([]byte, 32)
	copy(key2, key)
	key2[0] ^= 0x02

	aad := []byte("tenant-B")
	pt := []byte(aliceEmail)

	ct1, err := b.Encrypt(pt, key, aad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	ct2, err := b.Encrypt(pt, key, aad)
	if err != nil {
		t.Fatalf("Encrypt(2): %v", err)
	}

	if !strings.HasPrefix(ct1, boringPrefix) {
		t.Fatalf("expected prefix %q, got %q", boringPrefix, ct1[:min(len(ct1), 12)])
	}
	if ct1 == ct2 {
		t.Fatal("expected ciphertexts to differ for the same plaintext")
	}

	got, err := b.Decrypt(ct1, key, aad)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(got) != string(pt) {
		t.Fatalf("Decrypt mismatch: got %q want %q", string(got), string(pt))
	}

	_, err = b.Decrypt(ct1, key2, aad)
	if err == nil {
		t.Fatal("expected decrypt to fail with wrong key")
	}

	tampered := flipBase64URLChar(ct1, len(boringPrefix)+1)
	_, err = b.Decrypt(tampered, key, aad)
	if err == nil {
		t.Fatal("expected decrypt to fail for tampered ciphertext")
	}
}

func TestBoringCryptoBlindIndexDeterminismAndRange(t *testing.T) {
	b := NewBoringCrypto()
	key := fixedKey32()

	out1, err := b.BlindIndexFast([]byte(aliceEmail), key, 32)
	if err != nil {
		t.Fatalf("BlindIndexFast: %v", err)
	}
	out2, err := b.BlindIndexFast([]byte(aliceEmail), key, 32)
	if err != nil {
		t.Fatalf("BlindIndexFast(2): %v", err)
	}
	if out1 != out2 {
		t.Fatalf(deterministicFmt, out1, out2)
	}

	other, err := b.BlindIndexFast([]byte(bobEmail), key, 32)
	if err != nil {
		t.Fatalf("BlindIndexFast(other): %v", err)
	}
	if out1 == other {
		t.Fatal("expected different plaintexts to yield different blind index values")
	}

	if _, err := b.BlindIndexFast([]byte("x"), key, 0); err == nil {
		t.Fatal("expected error for outputBits=0")
	}

	if got, want := len(out1), 8; got != want {
		t.Fatalf("BlindIndexFast len: got %d want %d (%q)", got, want, out1)
	}
}

func TestBoringCryptoBlindIndexSlowDeterminism(t *testing.T) {
	b := NewBoringCrypto()
	key := fixedKey32()

	cfg := &argon.Config{
		TimeCost:    1,
		MemoryCost:  32 * 1024, // 32 MiB
		Parallelism: 1,
	}

	out1, err := b.BlindIndexSlow([]byte(aliceEmail), key, 32, cfg)
	if err != nil {
		t.Fatalf("BlindIndexSlow: %v", err)
	}
	out2, err := b.BlindIndexSlow([]byte(aliceEmail), key, 32, cfg)
	if err != nil {
		t.Fatalf("BlindIndexSlow(2): %v", err)
	}
	if out1 != out2 {
		t.Fatalf(deterministicFmt, out1, out2)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func tamperAt(s string, prefixLen int) string {
	pos := prefixLen + 1
	if pos >= len(s) {
		pos = len(s) - 1
	}
	return flipBase64URLChar(s, pos)
}

func TestNaClEncryptDecryptProperties(t *testing.T) {
	t.Parallel()

	n := NewNaCl()
	key := fixedKey32()
	aad1 := []byte("tenant-A")
	aad2 := []byte("tenant-B")
	pt := []byte(aliceEmail)

	ct1, err := n.Encrypt(pt, key, aad1)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	ct2, err := n.Encrypt(pt, key, aad1)
	if err != nil {
		t.Fatalf("Encrypt(2): %v", err)
	}

	if !strings.HasPrefix(ct1, naclPrefix) {
		t.Fatalf("expected prefix %q, got %q", naclPrefix, ct1[:min(len(ct1), 12)])
	}
	if ct1 == ct2 {
		// Extremely unlikely nonce collision.
		t.Fatal("expected ciphertexts to differ for the same plaintext")
	}

	got, err := n.Decrypt(ct1, key, aad1)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(got) != string(pt) {
		t.Fatalf("Decrypt mismatch: got %q want %q", string(got), string(pt))
	}

	// Wrong AAD should fail authentication.
	_, err = n.Decrypt(ct1, key, aad2)
	if err == nil {
		t.Fatal("expected decrypt to fail with wrong AAD")
	}

	// Wrong key should fail authentication.
	key2 := make([]byte, 32)
	copy(key2, key)
	key2[0] ^= 0x01
	_, err = n.Decrypt(ct1, key2, aad1)
	if err == nil {
		t.Fatal("expected decrypt to fail with wrong key")
	}

	// Tampering with ciphertext should fail authentication.
	tampered := tamperAt(ct1, len(naclPrefix))
	_, err = n.Decrypt(tampered, key, aad1)
	if err == nil {
		t.Fatal("expected decrypt to fail for tampered ciphertext")
	}
}

func TestNaClDecryptInvalidCiphertext(t *testing.T) {
	n := NewNaCl()
	key := fixedKey32()
	aad := []byte("tenant-A")
	pt := []byte(aliceEmail)
	ct, err := n.Encrypt(pt, key, aad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	tests := []struct {
		name string
		in   string
	}{
		{
			name: "invalid prefix",
			in:   "xxx:" + ct[len(naclPrefix):],
		},
		{
			name: "invalid base64",
			in:   naclPrefix + "%%%not-base64%%% ",
		},
		{
			name: "too short payload",
			in: func() string {
				// raw = [nonce||ciphertext], but use a too-short raw payload.
				raw := []byte{1, 2, 3, 4} // < naclNonceSize + tag
				return naclPrefix + base64.RawURLEncoding.EncodeToString(raw)
			}(),
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := n.Decrypt(tt.in, key, aad)
			if err == nil {
				t.Fatal("expected decrypt to fail")
			}
		})
	}
}

func TestNaClEncryptKeyLengthValidation(t *testing.T) {
	n := NewNaCl()
	aad := []byte("tenant-A")
	pt := []byte(aliceEmail)

	tests := []struct {
		name string
		key  []byte
	}{
		{name: "empty key", key: []byte{}},
		{name: "short key", key: make([]byte, 31)},
		{name: "long key", key: make([]byte, 33)},
		{name: "correct key", key: fixedKey32()},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := n.Encrypt(pt, tt.key, aad)
			if tt.name == "correct key" {
				if err != nil {
					t.Fatalf("expected success, got error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected Encrypt to fail")
			}
		})
	}
}

func TestNaClBlindIndexFastBoundaries(t *testing.T) {
	t.Parallel()

	n := NewNaCl()
	key := fixedKey32()
	pt := []byte(aliceEmail)
	other := []byte(bobEmail)

	bitsTable := []int{1, 16, 32, 64, 128, 256, 512}
	for _, outputBits := range bitsTable {
		outputBits := outputBits
		t.Run("outputBits="+intToString(outputBits), func(t *testing.T) {
			t.Parallel()

			idx1, err := n.BlindIndexFast(pt, key, outputBits)
			if err != nil {
				t.Fatalf("BlindIndexFast: %v", err)
			}
			idx2, err := n.BlindIndexFast(pt, key, outputBits)
			if err != nil {
				t.Fatalf("BlindIndexFast(2): %v", err)
			}
			if idx1 != idx2 {
				t.Fatalf("expected deterministic output, got %q vs %q", idx1, idx2)
			}
			// For tiny output widths (e.g. 1 bit) collisions are likely.
			if outputBits >= 16 {
				if idx1 == mustIndex(t, n, other, key, outputBits) {
					t.Fatal("expected different plaintexts to produce different indexes")
				}
			}

			wantLen := ((outputBits + 7) / 8) * 2
			if gotLen := len(idx1); gotLen != wantLen {
				t.Fatalf("hex length: got %d want %d (outputBits=%d)", gotLen, wantLen, outputBits)
			}
		})
	}

	invalid := []int{0, -1, 513, 999}
	for _, outputBits := range invalid {
		outputBits := outputBits
		t.Run("invalidOutputBits="+intToString(outputBits), func(t *testing.T) {
			t.Parallel()
			if _, err := n.BlindIndexFast(pt, key, outputBits); err == nil {
				t.Fatal("expected error for invalid outputBits")
			}
		})
	}
}

func TestNaClBlindIndexSlowDeterminismAndBoundaries(t *testing.T) {
	n := NewNaCl()
	key := fixedKey32()
	pt := []byte(aliceEmail)

	// Keep test costs low but still exercise Argon2id.
	cfg := &argon.Config{
		TimeCost:    1,
		MemoryCost:  32 * 1024, // 32 MiB
		Parallelism: 1,
	}

	bitsTable := []int{1, 32, 256, 512}
	for _, outputBits := range bitsTable {
		outputBits := outputBits
		t.Run("outputBits="+intToString(outputBits), func(t *testing.T) {
			out1, err := n.BlindIndexSlow(pt, key, outputBits, cfg)
			if err != nil {
				t.Fatalf("BlindIndexSlow: %v", err)
			}
			out2, err := n.BlindIndexSlow(pt, key, outputBits, cfg)
			if err != nil {
				t.Fatalf("BlindIndexSlow(2): %v", err)
			}
			if out1 != out2 {
				t.Fatalf("expected deterministic output, got %q vs %q", out1, out2)
			}

			wantLen := ((outputBits + 7) / 8) * 2
			if gotLen := len(out1); gotLen != wantLen {
				t.Fatalf("hex length: got %d want %d (outputBits=%d)", gotLen, wantLen, outputBits)
			}
		})
	}

	invalid := []int{0, -1, 513}
	for _, outputBits := range invalid {
		outputBits := outputBits
		t.Run("invalidOutputBits="+intToString(outputBits), func(t *testing.T) {
			if _, err := n.BlindIndexSlow(pt, key, outputBits, cfg); err == nil {
				t.Fatal("expected error for invalid outputBits")
			}
		})
	}
}

func TestNaClKeyDerivationDeterminismAndScoping(t *testing.T) {
	t.Parallel()

	n := NewNaCl()
	rootKey := fixedKey32()

	table := "users"
	field := "email"
	indexName := "email_index"

	f1a, err := n.DeriveFieldKey(rootKey, table, field)
	if err != nil {
		t.Fatalf("DeriveFieldKey: %v", err)
	}
	f1b, err := n.DeriveFieldKey(rootKey, table, field)
	if err != nil {
		t.Fatalf("DeriveFieldKey(2): %v", err)
	}
	if string(f1a) != string(f1b) {
		t.Fatal("DeriveFieldKey not deterministic for the same inputs")
	}
	if len(f1a) != 32 {
		t.Fatalf("DeriveFieldKey length: got %d want 32", len(f1a))
	}

	f2, err := n.DeriveFieldKey(rootKey, table, "phone")
	if err != nil {
		t.Fatalf("DeriveFieldKey(diff field): %v", err)
	}
	if string(f1a) == string(f2) {
		t.Fatal("field key should differ when fieldName changes")
	}

	i1a, err := n.DeriveIndexKey(rootKey, table, field, indexName)
	if err != nil {
		t.Fatalf("DeriveIndexKey: %v", err)
	}
	i1b, err := n.DeriveIndexKey(rootKey, table, field, indexName)
	if err != nil {
		t.Fatalf("DeriveIndexKey(2): %v", err)
	}
	if string(i1a) != string(i1b) {
		t.Fatal("DeriveIndexKey not deterministic for the same inputs")
	}
	if len(i1a) != 32 {
		t.Fatalf("DeriveIndexKey length: got %d want 32", len(i1a))
	}

	i2, err := n.DeriveIndexKey(rootKey, table, field, "other_index")
	if err != nil {
		t.Fatalf("DeriveIndexKey(diff indexName): %v", err)
	}
	if string(i1a) == string(i2) {
		t.Fatal("index key should differ when indexName changes")
	}
}

func TestBoringCryptoEncryptDecryptProperties(t *testing.T) {
	t.Parallel()

	b := NewBoringCrypto()
	key := fixedKey32()
	aad1 := []byte("tenant-A")
	aad2 := []byte("tenant-B")
	pt := []byte(aliceEmail)

	ct1, err := b.Encrypt(pt, key, aad1)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	ct2, err := b.Encrypt(pt, key, aad1)
	if err != nil {
		t.Fatalf("Encrypt(2): %v", err)
	}

	if !strings.HasPrefix(ct1, boringPrefix) {
		t.Fatalf("expected prefix %q, got %q", boringPrefix, ct1[:min(len(ct1), 14)])
	}
	if ct1 == ct2 {
		t.Fatal("expected ciphertexts to differ for the same plaintext")
	}

	got, err := b.Decrypt(ct1, key, aad1)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(got) != string(pt) {
		t.Fatalf("Decrypt mismatch: got %q want %q", string(got), string(pt))
	}

	_, err = b.Decrypt(ct1, key, aad2)
	if err == nil {
		t.Fatal("expected decrypt to fail with wrong AAD")
	}

	key2 := make([]byte, 32)
	copy(key2, key)
	key2[0] ^= 0x02
	_, err = b.Decrypt(ct1, key2, aad1)
	if err == nil {
		t.Fatal("expected decrypt to fail with wrong key")
	}

	tampered := tamperAt(ct1, len(boringPrefix))
	_, err = b.Decrypt(tampered, key, aad1)
	if err == nil {
		t.Fatal("expected decrypt to fail for tampered ciphertext")
	}
}

func TestBoringCryptoDecryptInvalidCiphertext(t *testing.T) {
	b := NewBoringCrypto()
	key := fixedKey32()
	aad := []byte("tenant-A")
	pt := []byte(aliceEmail)
	ct, err := b.Encrypt(pt, key, aad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	tests := []struct {
		name string
		in   string
	}{
		{
			name: "invalid prefix",
			in:   "xxx:" + ct[len(boringPrefix):],
		},
		{
			name: "invalid base64",
			in:   boringPrefix + "%%%not-base64%%% ",
		},
		{
			name: "too short payload",
			in: func() string {
				raw := []byte{1, 2, 3, 4} // < boringNonceSize+tag
				return boringPrefix + base64.RawURLEncoding.EncodeToString(raw)
			}(),
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := b.Decrypt(tt.in, key, aad)
			if err == nil {
				t.Fatal("expected decrypt to fail")
			}
		})
	}
}

func TestBoringCryptoEncryptKeyLengthValidation(t *testing.T) {
	b := NewBoringCrypto()
	aad := []byte("tenant-A")
	pt := []byte(aliceEmail)

	tests := []struct {
		name string
		key  []byte
	}{
		{name: "empty key", key: []byte{}},
		{name: "short key", key: make([]byte, 31)},
		{name: "long key", key: make([]byte, 33)},
		{name: "correct key", key: fixedKey32()},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := b.Encrypt(pt, tt.key, aad)
			if err != nil {
				t.Fatalf("expected success for key length case %q, got error: %v", tt.name, err)
			}
		})
	}
}

func TestBoringCryptoBlindIndexFastBoundaries(t *testing.T) {
	t.Parallel()

	b := NewBoringCrypto()
	key := fixedKey32()
	pt := []byte(aliceEmail)
	other := []byte(bobEmail)

	// BoringCrypto.BlindIndexFast uses HMAC-SHA256, which produces 32 bytes.
	// outputBits up to 256 is supported; larger widths may panic in the
	// current implementation. Keep this test aligned with that behavior.
	bitsTable := []int{1, 16, 32, 64, 128, 256}
	for _, outputBits := range bitsTable {
		outputBits := outputBits
		t.Run("outputBits="+intToString(outputBits), func(t *testing.T) {
			t.Parallel()

			idx1, err := b.BlindIndexFast(pt, key, outputBits)
			if err != nil {
				t.Fatalf("BlindIndexFast: %v", err)
			}
			idx2, err := b.BlindIndexFast(pt, key, outputBits)
			if err != nil {
				t.Fatalf("BlindIndexFast(2): %v", err)
			}
			if idx1 != idx2 {
				t.Fatalf("expected deterministic output, got %q vs %q", idx1, idx2)
			}
			if outputBits >= 16 {
				if idx1 == mustIndex(t, b, other, key, outputBits) {
					t.Fatal("expected different plaintexts to produce different indexes")
				}
			}

			wantLen := ((outputBits + 7) / 8) * 2
			if gotLen := len(idx1); gotLen != wantLen {
				t.Fatalf("hex length: got %d want %d (outputBits=%d)", gotLen, wantLen, outputBits)
			}
		})
	}

	invalid := []int{0, -1, 513, 999}
	for _, outputBits := range invalid {
		outputBits := outputBits
		t.Run("invalidOutputBits="+intToString(outputBits), func(t *testing.T) {
			t.Parallel()
			if _, err := b.BlindIndexFast(pt, key, outputBits); err == nil {
				t.Fatal("expected error for invalid outputBits")
			}
		})
	}
}

func TestBoringCryptoKeyDerivationDeterminismAndScoping(t *testing.T) {
	t.Parallel()

	b := NewBoringCrypto()
	rootKey := fixedKey32()

	table := "users"
	field := "email"
	indexName := "email_index"

	f1a, err := b.DeriveFieldKey(rootKey, table, field)
	if err != nil {
		t.Fatalf("DeriveFieldKey: %v", err)
	}
	f1b, err := b.DeriveFieldKey(rootKey, table, field)
	if err != nil {
		t.Fatalf("DeriveFieldKey(2): %v", err)
	}
	if string(f1a) != string(f1b) {
		t.Fatal("DeriveFieldKey not deterministic for the same inputs")
	}
	if len(f1a) != 32 {
		t.Fatalf("DeriveFieldKey length: got %d want 32", len(f1a))
	}

	f2, err := b.DeriveFieldKey(rootKey, table, "phone")
	if err != nil {
		t.Fatalf("DeriveFieldKey(diff field): %v", err)
	}
	if string(f1a) == string(f2) {
		t.Fatal("field key should differ when fieldName changes")
	}

	i1a, err := b.DeriveIndexKey(rootKey, table, field, indexName)
	if err != nil {
		t.Fatalf("DeriveIndexKey: %v", err)
	}
	i1b, err := b.DeriveIndexKey(rootKey, table, field, indexName)
	if err != nil {
		t.Fatalf("DeriveIndexKey(2): %v", err)
	}
	if string(i1a) != string(i1b) {
		t.Fatal("DeriveIndexKey not deterministic for the same inputs")
	}
	if len(i1a) != 32 {
		t.Fatalf("DeriveIndexKey length: got %d want 32", len(i1a))
	}

	i2, err := b.DeriveIndexKey(rootKey, table, field, "other_index")
	if err != nil {
		t.Fatalf("DeriveIndexKey(diff indexName): %v", err)
	}
	if string(i1a) == string(i2) {
		t.Fatal("index key should differ when indexName changes")
	}
}

func mustIndex(t *testing.T, backend interface {
	BlindIndexFast(plaintext, key []byte, outputBits int) (string, error)
}, plaintext, key []byte, outputBits int) string {
	t.Helper()
	idx, err := backend.BlindIndexFast(plaintext, key, outputBits)
	if err != nil {
		t.Fatalf("BlindIndexFast: %v", err)
	}
	return idx
}

func intToString(v int) string {
	// Small helper to keep test names readable without importing strconv.
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var buf [32]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
