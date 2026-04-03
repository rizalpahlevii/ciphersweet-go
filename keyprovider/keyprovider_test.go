package keyprovider

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

const testHexKey = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

const (
	keyErrFmt       = "Key: %v"
	keyByteMismatch = "Key byte %d mismatch"
	expectedErrMsg  = "expected error"
)

func mustDecodeHexKey(t *testing.T) []byte {
	t.Helper()
	b, err := hex.DecodeString(testHexKey)
	if err != nil {
		t.Fatalf("hex.DecodeString: %v", err)
	}
	return b
}

func TestStringProviderTrimmingAndCopy(t *testing.T) {
	t.Parallel()

	want := mustDecodeHexKey(t)

	sp, err := NewStringProvider(" \n\t" + testHexKey + "\n ")
	if err != nil {
		t.Fatalf("NewStringProvider: %v", err)
	}

	got1, err := sp.Key()
	if err != nil {
		t.Fatalf(keyErrFmt, err)
	}
	if len(got1) != 32 {
		t.Fatalf("Key len: got %d want 32", len(got1))
	}

	for i := range want {
		if got1[i] != want[i] {
			t.Fatalf(keyByteMismatch, i)
		}
	}

	// Key() must return a copy.
	got1[0] ^= 0xFF
	got2, err := sp.Key()
	if err != nil {
		t.Fatalf("Key(2): %v", err)
	}
	if got2[0] != want[0] {
		t.Fatalf("Key must not be affected by caller mutation: got %02x want %02x", got2[0], want[0])
	}
}

func TestStringProviderInvalidInputs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
	}{
		{name: "non-hex", in: "not-hex"},
		{name: "too short", in: testHexKey[:10]},
		{name: "too long", in: testHexKey + "00"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := NewStringProvider(tt.in)
			if err == nil {
				t.Fatal(expectedErrMsg)
			}
		})
	}
}

func TestEnvProvider(t *testing.T) {
	varName := "CIPHERSWEET_KEY_TEST"

	t.Run("missing env var returns error", func(t *testing.T) {
		t.Setenv(varName, "")

		kp := NewEnvProvider(varName)
		_, err := kp.Key()
		if err == nil {
			t.Fatal(expectedErrMsg)
		}
	})

	t.Run("set env var returns decoded key", func(t *testing.T) {
		t.Setenv(varName, testHexKey)
		kp := NewEnvProvider(varName)
		got, err := kp.Key()
		if err != nil {
			t.Fatalf(keyErrFmt, err)
		}
		want := mustDecodeHexKey(t)
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf(keyByteMismatch, i)
			}
		}
	})
}

func TestFileProvider(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "ciphersweet.key")

	if err := os.WriteFile(keyPath, []byte(testHexKey+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	kp := NewFileProvider(keyPath)
	got, err := kp.Key()
	if err != nil {
		t.Fatalf(keyErrFmt, err)
	}
	want := mustDecodeHexKey(t)
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf(keyByteMismatch, i)
		}
	}

	t.Run("invalid file content returns error", func(t *testing.T) {
		t.Parallel()

		badPath := filepath.Join(tmpDir, "bad.key")
		if err := os.WriteFile(badPath, []byte("not-hex\n"), 0o600); err != nil {
			t.Fatalf("WriteFile(bad): %v", err)
		}

		kp := NewFileProvider(badPath)
		_, err := kp.Key()
		if err == nil {
			t.Fatal(expectedErrMsg)
		}
	})
}

func TestRandomProvider(t *testing.T) {
	t.Parallel()

	t.Run("zero-valued RandomProvider returns error", func(t *testing.T) {
		t.Parallel()

		var rp RandomProvider
		_, err := rp.Key()
		if err == nil {
			t.Fatal(expectedErrMsg)
		}
	})

	t.Run("NewRandomProvider returns 32-byte key and returns copies", func(t *testing.T) {
		t.Parallel()

		rp, err := NewRandomProvider()
		if err != nil {
			t.Fatalf("NewRandomProvider: %v", err)
		}

		k1, err := rp.Key()
		if err != nil {
			t.Fatalf("Key(1): %v", err)
		}
		if len(k1) != 32 {
			t.Fatalf("Key(1) len: got %d want 32", len(k1))
		}
		original0 := k1[0]

		k1[0] ^= 0xFF
		k2, err := rp.Key()
		if err != nil {
			t.Fatalf("Key(2): %v", err)
		}
		if k2[0] != original0 {
			t.Fatalf("Key must return copies: got %02x want %02x", k2[0], original0)
		}

		if got := len(rp.HexString()); got != 64 {
			t.Fatalf("HexString len: got %d want 64", got)
		}
	})

	t.Run("MustRandomProvider", func(t *testing.T) {
		t.Parallel()
		rp := MustRandomProvider()
		if got := len(rp.HexString()); got != 64 {
			t.Fatalf("MustRandomProvider HexString len: got %d want 64", got)
		}
	})
}
