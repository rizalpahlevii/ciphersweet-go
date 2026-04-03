package row

import (
	"testing"

	"github.com/rizalpahlevii/ciphersweet-go/backend"
	"github.com/rizalpahlevii/ciphersweet-go/blindindex"
	"github.com/rizalpahlevii/ciphersweet-go/blindindex/transform"
	"github.com/rizalpahlevii/ciphersweet-go/engine"
	"github.com/rizalpahlevii/ciphersweet-go/keyprovider"
)

const testHexKey = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

const (
	aliceLower = "alice@example.com"
	aliceMixed = "Alice@Example.com"

	prepStorageErrFmt = "PrepareForStorage: %v"
	decryptRowErrFmt  = "DecryptRow: %v"
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

func TestEncryptedRowLenientAndStrictMissingFields(t *testing.T) {
	t.Parallel()

	eng := newTestEngine(t)
	data := RowData{"email": aliceLower}

	t.Run("lenient missing required fields are skipped", func(t *testing.T) {
		t.Parallel()

		er := New(eng, "users").
			AddField("email").
			AddField("phone")

		enc, _, err := er.PrepareForStorage(data)
		if err != nil {
			t.Fatalf(prepStorageErrFmt, err)
		}
		if _, ok := enc["email"]; !ok {
			t.Fatal("expected email ciphertext to be present")
		}
		if _, ok := enc["phone"]; ok {
			t.Fatal("did not expect phone ciphertext in lenient mode")
		}

		plain, err := er.DecryptRow(enc)
		if err != nil {
			t.Fatalf(decryptRowErrFmt, err)
		}
		if got := plain["email"]; got != aliceLower {
			t.Fatalf("email plaintext mismatch: got %q want %q", got, aliceLower)
		}
		if _, ok := plain["phone"]; ok {
			t.Fatal("did not expect phone plaintext in lenient mode")
		}
	})

	t.Run("strict missing required fields error", func(t *testing.T) {
		t.Parallel()

		er := New(eng, "users").
			AddField("email").
			AddField("phone").
			WithStrict()

		_, _, err := er.PrepareForStorage(data)
		if err == nil {
			t.Fatal("expected PrepareForStorage to fail in strict mode")
		}
	})
}

func TestEncryptedRowOptionalEmptySkipsEncryptionAndIndexes(t *testing.T) {
	t.Parallel()

	eng := newTestEngine(t)

	er := New(eng, "users").
		AddField("email").
		AddOptionalTextField("middle_name").
		AddBlindIndex("middle_name",
			blindindex.New("middle_index",
				blindindex.WithBits(32),
				blindindex.WithFast(),
				blindindex.WithTransform(transform.TrimSpace{}),
			),
		).
		AddBlindIndex("email",
			blindindex.New("email_index",
				blindindex.WithBits(32),
				blindindex.WithFast(),
				blindindex.WithTransform(transform.Lowercase{}),
			),
		)

	data := RowData{
		"email":       aliceMixed,
		"middle_name": "",
	}

	enc, indexes, err := er.PrepareForStorage(data)
	if err != nil {
		t.Fatalf(prepStorageErrFmt, err)
	}

	if got := enc["middle_name"]; got != "" {
		t.Fatalf("expected optional empty field to store \"\", got %q", got)
	}
	if _, ok := indexes["middle_index"]; ok {
		t.Fatal("expected middle_index to be omitted when middle_name plaintext is empty")
	}
	if indexes["email_index"] == "" {
		t.Fatal("expected email_index to be present")
	}

	plain, err := er.DecryptRow(enc)
	if err != nil {
		t.Fatalf(decryptRowErrFmt, err)
	}
	if got := plain["middle_name"]; got != "" {
		t.Fatalf("optional empty plaintext mismatch: got %q want %q", got, "")
	}

	// Even though PrepareForStorage omitted it, GetBlindIndex should still work.
	idx, err := er.GetBlindIndex("middle_name", "", "middle_index")
	if err != nil {
		t.Fatalf("GetBlindIndex: %v", err)
	}
	if idx == "" {
		t.Fatal("expected non-empty blind index string")
	}
}

func TestEncryptedRowRoundTripAndBlindIndexes(t *testing.T) {
	t.Parallel()

	eng := newTestEngine(t)

	er := New(eng, "users").
		AddField("email").
		AddField("phone").
		AddOptionalTextField("middle_name").
		AddBlindIndex("email",
			blindindex.New("email_index",
				blindindex.WithBits(32),
				blindindex.WithFast(),
				blindindex.WithTransform(transform.Lowercase{}),
			),
		).
		AddBlindIndex("email",
			blindindex.New("email_first_char",
				blindindex.WithBits(16),
				blindindex.WithFast(),
				blindindex.WithTransform(transform.FirstCharacter{}),
			),
		)

	original := RowData{
		"email":       aliceMixed,
		"phone":       "+1-555-0100",
		"middle_name": "  Bob  ",
	}

	enc, indexes, err := er.PrepareForStorage(original)
	if err != nil {
		t.Fatalf(prepStorageErrFmt, err)
	}

	if enc["email"] == original["email"] {
		t.Fatal("email ciphertext should differ from plaintext")
	}
	if enc["phone"] == original["phone"] {
		t.Fatal("phone ciphertext should differ from plaintext")
	}
	if enc["middle_name"] == original["middle_name"] {
		t.Fatal("middle_name ciphertext should differ from plaintext when non-empty")
	}

	plain, err := er.DecryptRow(enc)
	if err != nil {
		t.Fatalf(decryptRowErrFmt, err)
	}
	for k, want := range original {
		if got := plain[k]; got != want {
			t.Fatalf("plaintext mismatch for %q: got %q want %q", k, got, want)
		}
	}

	wantEmailIdx := indexes["email_index"]
	idx, err := er.GetBlindIndex("email", "ALICE@EXAMPLE.COM", "email_index")
	if err != nil {
		t.Fatalf("GetBlindIndex(email_index): %v", err)
	}
	if idx != wantEmailIdx {
		t.Fatalf("email_index mismatch: got %q want %q", idx, wantEmailIdx)
	}

	all, err := er.GetAllBlindIndexes("email", aliceMixed)
	if err != nil {
		t.Fatalf("GetAllBlindIndexes: %v", err)
	}
	if all["email_index"] != indexes["email_index"] {
		t.Fatalf("GetAllBlindIndexes email_index mismatch: got %q want %q", all["email_index"], indexes["email_index"])
	}
	if all["email_first_char"] != indexes["email_first_char"] {
		t.Fatalf("GetAllBlindIndexes email_first_char mismatch: got %q want %q", all["email_first_char"], indexes["email_first_char"])
	}
}

func TestEncryptedRowGetBlindIndexErrors(t *testing.T) {
	t.Parallel()

	eng := newTestEngine(t)
	er := New(eng, "users").
		AddField("email").
		AddBlindIndex("email", blindindex.New("email_index", blindindex.WithBits(32), blindindex.WithFast()))

	if _, err := er.GetBlindIndex("email", aliceLower, "missing_index"); err == nil {
		t.Fatal("expected GetBlindIndex to fail for missing indexName")
	}

	_, err := er.GetAllBlindIndexes("phone", aliceLower)
	if err == nil {
		t.Fatal("expected GetAllBlindIndexes to fail for fieldName with no indexes")
	}
}

func TestEncryptedRowWrongRootKeyAndTamperingFails(t *testing.T) {
	t.Parallel()

	engGood := newTestEngine(t)

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

	erGood := New(engGood, "users").
		AddField("email").
		AddBlindIndex("email", blindindex.New("email_index", blindindex.WithBits(32), blindindex.WithFast()))

	data := RowData{"email": aliceLower}
	enc, _, err := erGood.PrepareForStorage(data)
	if err != nil {
		t.Fatalf(prepStorageErrFmt, err)
	}

	erBad := New(engBad, "users").
		AddField("email").
		AddBlindIndex("email", blindindex.New("email_index", blindindex.WithBits(32), blindindex.WithFast()))

	_, err = erBad.DecryptRow(enc)
	if err == nil {
		t.Fatal("expected DecryptRow to fail with wrong root key")
	}

	// Tamper ciphertext should also fail.
	encBad := make(EncryptedData, len(enc))
	for k, v := range enc {
		encBad[k] = v
	}
	encBad["email"] = tamperCiphertextLastByte(encBad["email"])

	_, err = erGood.DecryptRow(encBad)
	if err == nil {
		t.Fatal("expected DecryptRow to fail for tampered ciphertext")
	}
}

func TestEncryptedRowAddFields(t *testing.T) {
	eng := newTestEngine(t)
	er := New(eng, "users").
		AddBooleanField("is_active").
		AddIntegerField("age").
		AddFloatField("score")

	data := RowData{
		"is_active": "true",
		"age":       "25",
		"score":     "95.5",
	}
	enc, _, err := er.PrepareForStorage(data)
	if err != nil {
		t.Fatal(err)
	}
	if enc["is_active"] == "true" || enc["age"] == "25" || enc["score"] == "95.5" {
		t.Fatal("Fields not encrypted")
	}

	plain, err := er.DecryptRow(enc)
	if err != nil {
		t.Fatal(err)
	}
	if plain["is_active"] != "true" || plain["age"] != "25" || plain["score"] != "95.5" {
		t.Fatal("Fields not decrypted correctly")
	}
}
