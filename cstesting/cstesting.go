package cstesting

import (
	"testing"

	"github.com/rizalpahlevii/ciphersweet-go/backend"
	"github.com/rizalpahlevii/ciphersweet-go/blindindex"
	"github.com/rizalpahlevii/ciphersweet-go/blindindex/transform"
	"github.com/rizalpahlevii/ciphersweet-go/engine"
	"github.com/rizalpahlevii/ciphersweet-go/field"
	"github.com/rizalpahlevii/ciphersweet-go/keyprovider"
	"github.com/rizalpahlevii/ciphersweet-go/row"
)

// fixedHexKey is a deterministic 256-bit key for tests only.
// NEVER use in production.
const fixedHexKey = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

// ── Engine factories ──────────────────────────────────────────────────────────

// NewEngine returns a NaCl engine wired with the fixed test key.
func NewEngine(t testing.TB) *engine.Engine {
	t.Helper()
	kp, err := keyprovider.NewStringProvider(fixedHexKey)
	if err != nil {
		t.Fatalf("cstesting.NewEngine: %v", err)
	}
	eng, err := engine.New(backend.NewNaCl(), kp)
	if err != nil {
		t.Fatalf("cstesting.NewEngine: %v", err)
	}
	return eng
}

// NewBoringEngine returns a BoringCrypto engine wired with the fixed test key.
func NewBoringEngine(t testing.TB) *engine.Engine {
	t.Helper()
	kp, err := keyprovider.NewStringProvider(fixedHexKey)
	if err != nil {
		t.Fatalf("cstesting.NewBoringEngine: %v", err)
	}
	eng, err := engine.New(backend.NewBoringCrypto(), kp)
	if err != nil {
		t.Fatalf("cstesting.NewBoringEngine: %v", err)
	}
	return eng
}

// NewRandomEngine returns a NaCl engine with an ephemeral random key.
// Use when the test doesn't need deterministic ciphertexts.
func NewRandomEngine(t testing.TB) *engine.Engine {
	t.Helper()
	kp := keyprovider.MustRandomProvider()
	eng, err := engine.New(backend.NewNaCl(), kp)
	if err != nil {
		t.Fatalf("cstesting.NewRandomEngine: %v", err)
	}
	return eng
}

// ── Pre-built fields ──────────────────────────────────────────────────────────

// EmailField returns an EncryptedField for users.email with a 32-bit
// case-insensitive index named "email_index".
func EmailField(t testing.TB) *field.EncryptedField {
	t.Helper()
	return field.New(NewEngine(t), "users", "email").
		AddBlindIndex(blindindex.New("email_index",
			blindindex.WithBits(32),
			blindindex.WithFast(),
			blindindex.WithTransform(transform.Lowercase{}),
		))
}

// SSNField returns an EncryptedField for users.ssn with two indexes:
//   - "ssn_index"           — 32-bit full-SSN index
//   - "ssn_last_four_index" — 16-bit last-four-digits index
func SSNField(t testing.TB) *field.EncryptedField {
	t.Helper()
	return field.New(NewEngine(t), "users", "ssn").
		AddBlindIndex(blindindex.New("ssn_index",
			blindindex.WithBits(32),
			blindindex.WithFast(),
		)).
		AddBlindIndex(blindindex.New("ssn_last_four_index",
			blindindex.WithBits(16),
			blindindex.WithFast(),
			blindindex.WithTransform(transform.LastFourDigits{}),
		))
}

// UserRow returns an EncryptedRow for the users table covering email, phone,
// ssn, and middle_name (optional).
func UserRow(t testing.TB) *row.EncryptedRow {
	t.Helper()
	return row.New(NewEngine(t), "users").
		AddField("email").
		AddField("phone").
		AddField("ssn").
		AddOptionalTextField("middle_name").
		AddBlindIndex("email", blindindex.New("email_index",
			blindindex.WithBits(32),
			blindindex.WithFast(),
			blindindex.WithTransform(transform.Lowercase{}),
		)).
		AddBlindIndex("ssn", blindindex.New("ssn_last_four_index",
			blindindex.WithBits(16),
			blindindex.WithFast(),
			blindindex.WithTransform(transform.LastFourDigits{}),
		))
}

// ── Assertion helpers ─────────────────────────────────────────────────────────

// NoError fails the test immediately if err is non-nil.
func NoError(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// AssertDecrypts checks that ciphertext decrypts to wantPlaintext via ef.
func AssertDecrypts(t testing.TB, ef *field.EncryptedField, ciphertext, wantPlaintext string) {
	t.Helper()
	got, err := ef.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("AssertDecrypts: %v", err)
	}
	if got != wantPlaintext {
		t.Errorf("AssertDecrypts: got %q, want %q", got, wantPlaintext)
	}
}

// AssertIndexSearchable verifies that re-computing the blind index for plaintext
// produces the same value as storedIndexes[indexName].
func AssertIndexSearchable(
	t testing.TB,
	ef *field.EncryptedField,
	plaintext, indexName string,
	storedIndexes field.IndexMap,
) {
	t.Helper()
	computed, err := ef.GetBlindIndex(plaintext, indexName)
	if err != nil {
		t.Fatalf("AssertIndexSearchable: GetBlindIndex: %v", err)
	}
	stored, ok := storedIndexes[indexName]
	if !ok {
		t.Fatalf("AssertIndexSearchable: index %q not in storedIndexes", indexName)
	}
	if computed != stored {
		t.Errorf("AssertIndexSearchable [%s]: computed %q != stored %q", indexName, computed, stored)
	}
}

// AssertCiphertextDiffers verifies that two encryptions of the same plaintext
// produce different ciphertexts (probabilistic encryption sanity check).
func AssertCiphertextDiffers(t testing.TB, ef *field.EncryptedField, plaintext string) {
	t.Helper()
	ct1, _, err := ef.PrepareForStorage(plaintext)
	NoError(t, err)
	ct2, _, err := ef.PrepareForStorage(plaintext)
	NoError(t, err)
	if ct1 == ct2 {
		t.Errorf("AssertCiphertextDiffers: got identical ciphertexts for %q — nonce reuse?", plaintext)
	}
}

// AssertIndexStable verifies that two blind index computations of the same
// plaintext produce the same value (determinism check).
func AssertIndexStable(t testing.TB, ef *field.EncryptedField, plaintext, indexName string) {
	t.Helper()
	idx1, err := ef.GetBlindIndex(plaintext, indexName)
	NoError(t, err)
	idx2, err := ef.GetBlindIndex(plaintext, indexName)
	NoError(t, err)
	if idx1 != idx2 {
		t.Errorf("AssertIndexStable [%s]: two calls returned different values for the same input", indexName)
	}
}

// AssertRowDecrypts checks that er.DecryptRow(encData) matches wantData for
// every key in wantData.
func AssertRowDecrypts(
	t testing.TB,
	er *row.EncryptedRow,
	encData row.EncryptedData,
	wantData row.RowData,
) {
	t.Helper()
	got, err := er.DecryptRow(encData)
	if err != nil {
		t.Fatalf("AssertRowDecrypts: %v", err)
	}
	for f, want := range wantData {
		if got[f] != want {
			t.Errorf("AssertRowDecrypts [%s]: got %q, want %q", f, got[f], want)
		}
	}
}
