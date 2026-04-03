package field

import (
	"testing"

	"github.com/rizalpahlevii/ciphersweet-go/backend"
	"github.com/rizalpahlevii/ciphersweet-go/blindindex"
	"github.com/rizalpahlevii/ciphersweet-go/blindindex/transform"
	"github.com/rizalpahlevii/ciphersweet-go/engine"
	"github.com/rizalpahlevii/ciphersweet-go/keyprovider"
)

const testHexKey = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
const naclPrefix = "nacl:"
const (
	tenantA    = "tenant-A"
	tenantB    = "tenant-B"
	aliceMixed = "Alice@Example.com"
	aliceLower = "alice@example.com"

	prepStorageErrFmt = "PrepareForStorage: %v"
)

func newTestEngine(t *testing.T) *engine.Engine {
	t.Helper()

	kp, err := keyprovider.NewStringProvider(testHexKey)
	if err != nil {
		t.Fatalf("NewStringProvider: %v", err)
	}
	eng, err := engine.New(backend.NewNaCl(), kp)
	if err != nil {
		t.Fatalf("engine.New: %v", err)
	}
	return eng
}

func tamperCiphertextLastByte(s string) string {
	if len(s) == 0 {
		return s
	}
	b := []byte(s)
	b[len(b)-1] ^= 0x01
	return string(b)
}

func TestEncryptedFieldPrepareDecryptAndBlindIndex(t *testing.T) {
	t.Parallel()

	eng := newTestEngine(t)
	ef := New(eng, "users", "email").
		WithAAD([]byte(tenantA)).
		AddBlindIndex(blindindex.New(
			"email_index",
			blindindex.WithBits(32),
			blindindex.WithFast(),
			blindindex.WithTransform(transform.Lowercase{}),
		))

	ct, indexes, err := ef.PrepareForStorage(aliceMixed)
	if err != nil {
		t.Fatalf(prepStorageErrFmt, err)
	}
	if ct == "" {
		t.Fatal("ciphertext must not be empty")
	}
	if _, ok := indexes["email_index"]; !ok {
		t.Fatal("expected email_index in returned indexes")
	}
	if len(indexes) != 1 {
		t.Fatalf("expected exactly 1 index, got %d", len(indexes))
	}

	if !startsWith(ct, naclPrefix) {
		t.Fatalf("expected ciphertext prefix %q, got %q", naclPrefix, ct[:min(len(ct), len(naclPrefix))])
	}

	plain, err := ef.Decrypt(ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if plain != aliceMixed {
		t.Fatalf("plaintext mismatch: got %q want %q", plain, aliceMixed)
	}

	// blind index uses transformations; ensure it matches for different input casing.
	wantIdx := indexes["email_index"]

	idx1, err := ef.GetBlindIndex("ALICE@EXAMPLE.COM", "email_index")
	if err != nil {
		t.Fatalf("GetBlindIndex(upper): %v", err)
	}
	if idx1 != wantIdx {
		t.Fatalf("blind index mismatch: got %q want %q", idx1, wantIdx)
	}

	idx2, err := ef.GetBlindIndex(aliceLower, "email_index")
	if err != nil {
		t.Fatalf("GetBlindIndex(lower): %v", err)
	}
	if idx2 != wantIdx {
		t.Fatalf("blind index mismatch: got %q want %q", idx2, wantIdx)
	}

	all, err := ef.GetAllBlindIndexes(aliceMixed)
	if err != nil {
		t.Fatalf("GetAllBlindIndexes: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("GetAllBlindIndexes len: got %d want %d", len(all), 1)
	}
	if all["email_index"] != wantIdx {
		t.Fatalf("GetAllBlindIndexes value mismatch: got %q want %q", all["email_index"], wantIdx)
	}
}

func TestEncryptedFieldWrongAADFails(t *testing.T) {
	t.Parallel()

	eng := newTestEngine(t)

	efA := New(eng, "users", "email").
		WithAAD([]byte(tenantA)).
		AddBlindIndex(blindindex.New("email_index", blindindex.WithBits(32), blindindex.WithFast()))

	efB := New(eng, "users", "email").
		WithAAD([]byte(tenantB)).
		AddBlindIndex(blindindex.New("email_index", blindindex.WithBits(32), blindindex.WithFast()))

	ct, _, err := efA.PrepareForStorage(aliceLower)
	if err != nil {
		t.Fatalf(prepStorageErrFmt, err)
	}

	_, err = efB.Decrypt(ct)
	if err == nil {
		t.Fatal("expected Decrypt to fail with wrong AAD")
	}
}

func TestEncryptedFieldMissingIndexErrors(t *testing.T) {
	t.Parallel()

	eng := newTestEngine(t)
	ef := New(eng, "users", "email")

	if _, err := ef.GetBlindIndex(aliceLower, "email_index"); err == nil {
		t.Fatal("expected GetBlindIndex to fail for missing index")
	}

	all, err := ef.GetAllBlindIndexes(aliceLower)
	if err != nil {
		t.Fatalf("GetAllBlindIndexes: %v", err)
	}
	if len(all) != 0 {
		t.Fatalf("expected empty map for GetAllBlindIndexes, got %d entries", len(all))
	}
}

func TestEncryptedFieldTamperedCiphertextFails(t *testing.T) {
	t.Parallel()

	eng := newTestEngine(t)
	ef := New(eng, "users", "email").
		WithAAD([]byte(tenantA)).
		AddBlindIndex(blindindex.New("email_index", blindindex.WithBits(32), blindindex.WithFast()))

	ct, _, err := ef.PrepareForStorage(aliceLower)
	if err != nil {
		t.Fatalf(prepStorageErrFmt, err)
	}

	tampered := tamperCiphertextLastByte(ct)
	_, err = ef.Decrypt(tampered)
	if err == nil {
		t.Fatal("expected Decrypt to fail for tampered ciphertext")
	}
}

func TestEncryptedFieldMultipleBlindIndexes(t *testing.T) {
	t.Parallel()

	eng := newTestEngine(t)
	ef := New(eng, "users", "email").
		WithAAD([]byte(tenantA)).
		AddBlindIndex(blindindex.New("email_index_32", blindindex.WithBits(32), blindindex.WithFast())).
		AddBlindIndex(blindindex.New("email_index_16", blindindex.WithBits(16), blindindex.WithFast()))

	_, indexes, err := ef.PrepareForStorage(aliceLower)
	if err != nil {
		t.Fatalf(prepStorageErrFmt, err)
	}

	if indexes["email_index_32"] == "" {
		t.Fatal("missing email_index_32")
	}
	if indexes["email_index_16"] == "" {
		t.Fatal("missing email_index_16")
	}

	idx32, err := ef.GetBlindIndex(aliceLower, "email_index_32")
	if err != nil {
		t.Fatalf("GetBlindIndex email_index_32: %v", err)
	}
	if idx32 != indexes["email_index_32"] {
		t.Fatalf("email_index_32 mismatch: got %q want %q", idx32, indexes["email_index_32"])
	}
}

func TestEncryptedFieldWrongRootKeyFails(t *testing.T) {
	t.Parallel()

	kpGood, err := keyprovider.NewStringProvider(testHexKey)
	if err != nil {
		t.Fatalf("NewStringProvider(good): %v", err)
	}
	engGood, err := engine.New(backend.NewNaCl(), kpGood)
	if err != nil {
		t.Fatalf("engine.New(good): %v", err)
	}

	kpBad, err := keyprovider.NewStringProvider(
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e2f",
	)
	if err != nil {
		t.Fatalf("NewStringProvider(bad): %v", err)
	}
	engBad, err := engine.New(backend.NewNaCl(), kpBad)
	if err != nil {
		t.Fatalf("engine.New(bad): %v", err)
	}

	efGood := New(engGood, "users", "email").
		WithAAD([]byte(tenantA)).
		AddBlindIndex(blindindex.New("email_index", blindindex.WithBits(32), blindindex.WithFast()))

	ct, _, err := efGood.PrepareForStorage(aliceLower)
	if err != nil {
		t.Fatalf(prepStorageErrFmt, err)
	}

	efBad := New(engBad, "users", "email").
		WithAAD([]byte(tenantA)).
		AddBlindIndex(blindindex.New("email_index", blindindex.WithBits(32), blindindex.WithFast()))

	_, err = efBad.Decrypt(ct)
	if err == nil {
		t.Fatal("expected decrypt to fail for wrong root key")
	}
}

func startsWith(s, prefix string) bool {
	if len(prefix) > len(s) {
		return false
	}
	return s[:len(prefix)] == prefix
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
