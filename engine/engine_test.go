package engine

import (
	"errors"
	"sync"
	"testing"

	"github.com/rizalpahlevii/ciphersweet-go/argon"
	"github.com/rizalpahlevii/ciphersweet-go/backend"
	"github.com/rizalpahlevii/ciphersweet-go/keyprovider"
)

const fixedHexKey = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
const wrongHexKey = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1e"
const aliceEmail = "alice@example.com"

type errKeyProvider struct {
	err error
}

func (e errKeyProvider) Key() ([]byte, error) { return nil, e.err }

type badLenKeyProvider struct {
	keyLen int
}

func (b badLenKeyProvider) Key() ([]byte, error) {
	return make([]byte, b.keyLen), nil
}

func newEngine(t *testing.T, b backend.Backend, hexKey string) *Engine {
	t.Helper()

	kp, err := keyprovider.NewStringProvider(hexKey)
	if err != nil {
		t.Fatalf("NewStringProvider: %v", err)
	}
	eng, err := New(b, kp)
	if err != nil {
		t.Fatalf("engine.New: %v", err)
	}
	return eng
}

func TestNewKeyProviderErrors(t *testing.T) {
	t.Parallel()

	t.Run("keyprovider error", func(t *testing.T) {
		t.Parallel()

		_, err := New(backend.NewNaCl(), errKeyProvider{err: errors.New("boom")})
		// We don't depend on the exact wrapping string, just that it's non-nil.
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("keyprovider bad key length", func(t *testing.T) {
		t.Parallel()

		_, err := New(backend.NewNaCl(), badLenKeyProvider{keyLen: 31})
		if err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestEncryptDecryptNaClRoundTripAndAAD(t *testing.T) {
	t.Parallel()

	eng := newEngine(t, backend.NewNaCl(), fixedHexKey)
	plaintext := aliceEmail
	tableName := "users"
	fieldName := "email"

	aad1 := []byte("tenant-A")
	aad2 := []byte("tenant-B")

	ct, err := eng.EncryptField([]byte(plaintext), tableName, fieldName, aad1)
	if err != nil {
		t.Fatalf("EncryptField: %v", err)
	}

	got, err := eng.DecryptField(ct, tableName, fieldName, aad1)
	if err != nil {
		t.Fatalf("DecryptField: %v", err)
	}
	if string(got) != plaintext {
		t.Fatalf("plaintext mismatch: got %q want %q", string(got), plaintext)
	}

	// Wrong AAD must fail authentication.
	_, err = eng.DecryptField(ct, tableName, fieldName, aad2)
	if err == nil {
		t.Fatal("expected DecryptField to fail with wrong AAD")
	}

	// Wrong root key must fail authentication.
	engWrong := newEngine(t, backend.NewNaCl(), wrongHexKey)
	_, err = engWrong.DecryptField(ct, tableName, fieldName, aad1)
	if err == nil {
		t.Fatal("expected DecryptField to fail with wrong root key")
	}

	// Non-empty ciphertext tampering should fail.
	if len(ct) < 10 {
		t.Fatalf("unexpected ciphertext length: %d", len(ct))
	}
	b := []byte(ct)
	b[len(b)-1] ^= 1
	tampered := string(b)
	_, err = eng.DecryptField(tampered, tableName, fieldName, aad1)
	if err == nil {
		t.Fatal("expected DecryptField to fail for tampered ciphertext")
	}
}

func TestEncryptDecryptBoringRoundTrip(t *testing.T) {
	t.Parallel()

	eng := newEngine(t, backend.NewBoringCrypto(), fixedHexKey)
	plaintext := "bob@example.com"
	tableName := "users"
	fieldName := "email"
	aad := []byte("tenant-B")

	ct, err := eng.EncryptField([]byte(plaintext), tableName, fieldName, aad)
	if err != nil {
		t.Fatalf("EncryptField: %v", err)
	}

	got, err := eng.DecryptField(ct, tableName, fieldName, aad)
	if err != nil {
		t.Fatalf("DecryptField: %v", err)
	}
	if string(got) != plaintext {
		t.Fatalf("plaintext mismatch: got %q want %q", string(got), plaintext)
	}
}

func TestBlindIndexFastDeterminismAndScoping(t *testing.T) {
	t.Parallel()

	eng := newEngine(t, backend.NewNaCl(), fixedHexKey)

	tableName := "users"
	fieldName := "email"
	indexName := "email_index"
	transformed := aliceEmail
	outputBits := 256

	i1, err := eng.BlindIndexFast(transformed, tableName, fieldName, indexName, outputBits)
	if err != nil {
		t.Fatalf("BlindIndexFast: %v", err)
	}
	i2, err := eng.BlindIndexFast(transformed, tableName, fieldName, indexName, outputBits)
	if err != nil {
		t.Fatalf("BlindIndexFast(2): %v", err)
	}
	if i1 != i2 {
		t.Fatalf("determinism mismatch: got %q vs %q", i1, i2)
	}

	// Scoped to tableName.
	iTable, err := eng.BlindIndexFast(transformed, "users_v2", fieldName, indexName, outputBits)
	if err != nil {
		t.Fatalf("BlindIndexFast(table): %v", err)
	}
	if i1 == iTable {
		t.Fatal("expected different blind index for different tableName")
	}

	// Scoped to fieldName.
	iField, err := eng.BlindIndexFast(transformed, tableName, "phone", indexName, outputBits)
	if err != nil {
		t.Fatalf("BlindIndexFast(field): %v", err)
	}
	if i1 == iField {
		t.Fatal("expected different blind index for different fieldName")
	}

	// Scoped to indexName.
	iIndex, err := eng.BlindIndexFast(transformed, tableName, fieldName, "other_index", outputBits)
	if err != nil {
		t.Fatalf("BlindIndexFast(index): %v", err)
	}
	if i1 == iIndex {
		t.Fatal("expected different blind index for different indexName")
	}
}

func TestBlindIndexFastInvalidOutputBits(t *testing.T) {
	t.Parallel()

	eng := newEngine(t, backend.NewNaCl(), fixedHexKey)

	_, err := eng.BlindIndexFast("x", "users", "email", "email_index", 0)
	if err == nil {
		t.Fatal("expected error for outputBits=0")
	}

	_, err = eng.BlindIndexFast("x", "users", "email", "email_index", 513)
	if err == nil {
		t.Fatal("expected error for outputBits=513")
	}
}

func TestBlindIndexSlowDeterminismAndScoping(t *testing.T) {
	t.Parallel()

	eng := newEngine(t, backend.NewNaCl(), fixedHexKey)

	cfg := &argon.Config{
		TimeCost:    1,
		MemoryCost:  32 * 1024, // 32 MiB
		Parallelism: 1,
	}

	tableName := "users"
	fieldName := "email"
	indexName := "email_index"
	transformed := aliceEmail
	outputBits := 32

	i1, err := eng.BlindIndexSlow(transformed, tableName, fieldName, indexName, outputBits, cfg)
	if err != nil {
		t.Fatalf("BlindIndexSlow: %v", err)
	}
	i2, err := eng.BlindIndexSlow(transformed, tableName, fieldName, indexName, outputBits, cfg)
	if err != nil {
		t.Fatalf("BlindIndexSlow(2): %v", err)
	}
	if i1 != i2 {
		t.Fatalf("determinism mismatch: got %q vs %q", i1, i2)
	}

	// Scoped to indexName.
	iIndex, err := eng.BlindIndexSlow(transformed, tableName, fieldName, "other_index", outputBits, cfg)
	if err != nil {
		t.Fatalf("BlindIndexSlow(index): %v", err)
	}
	if i1 == iIndex {
		t.Fatal("expected different blind index for different indexName")
	}
}

func TestBlindIndexSlowInvalidOutputBits(t *testing.T) {
	t.Parallel()

	eng := newEngine(t, backend.NewNaCl(), fixedHexKey)

	cfg := &argon.Config{TimeCost: 1, MemoryCost: 16 * 1024, Parallelism: 1}
	_, err := eng.BlindIndexSlow("x", "users", "email", "email_index", 0, cfg)
	if err == nil {
		t.Fatal("expected error for outputBits=0")
	}
}

func TestEngineConcurrentAccess(t *testing.T) {
	eng := newEngine(t, backend.NewNaCl(), fixedHexKey)

	tableName := "users"
	fieldName := "email"
	indexName := "email_index"
	aad := []byte("tenant-A")
	plaintext := []byte(aliceEmail)

	outputBits := 256
	transformed := aliceEmail

	const workers = 16
	const iterations = 25

	var wg sync.WaitGroup
	wg.Add(workers)

	errs := make(chan error, workers*iterations)

	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			// Stagger slightly without using randomness (deterministic schedule).
			for i := 0; i < iterations; i++ {
				if err := encryptDecryptOnce(eng, tableName, fieldName, aad, plaintext); err != nil {
					errs <- err
					return
				}
				if err := blindIndexFastOnce(eng, transformed, tableName, fieldName, indexName, outputBits); err != nil {
					errs <- err
					return
				}
			}
		}()
	}

	wg.Wait()

	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent engine access failed: %v", err)
		}
	}
}

func encryptDecryptOnce(eng *Engine, tableName, fieldName string, aad, plaintext []byte) error {
	ct, err := eng.EncryptField(plaintext, tableName, fieldName, aad)
	if err != nil {
		return err
	}
	got, err := eng.DecryptField(ct, tableName, fieldName, aad)
	if err != nil {
		return err
	}
	if string(got) != string(plaintext) {
		return errors.New("plaintext mismatch")
	}
	return nil
}

func blindIndexFastOnce(eng *Engine, transformed, tableName, fieldName, indexName string, outputBits int) error {
	idx, err := eng.BlindIndexFast(transformed, tableName, fieldName, indexName, outputBits)
	if err != nil {
		return err
	}
	if idx == "" {
		return errors.New("empty blind index")
	}
	return nil
}
