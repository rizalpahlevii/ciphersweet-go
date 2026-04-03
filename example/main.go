package main

import (
	"fmt"
	"log"

	"github.com/rizalpahlevii/ciphersweet-go/backend"
	"github.com/rizalpahlevii/ciphersweet-go/blindindex"
	"github.com/rizalpahlevii/ciphersweet-go/engine"
	"github.com/rizalpahlevii/ciphersweet-go/field"
	"github.com/rizalpahlevii/ciphersweet-go/keyprovider"
	"github.com/rizalpahlevii/ciphersweet-go/row"
)

func main() {
	// ── Engine setup ──────────────────────────────────────────────────────────
	// In production: reads CIPHERSWEET_KEY from environment.
	// Generate a key: openssl rand -hex 32
	kp, err := keyprovider.NewStringProvider(
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
	)
	must(err)
	eng, err := engine.New(backend.NewNaCl(), kp)
	must(err)

	// ─────────────────────────────────────────────────────────────────────────
	fmt.Println("── 1. EncryptField / DecryptField ──────────────────────────────")
	// ─────────────────────────────────────────────────────────────────────────

	ct, err := eng.EncryptField([]byte("alice@example.com"), "users", "email", nil)
	must(err)
	fmt.Println("ciphertext :", ct)

	pt, err := eng.DecryptField(ct, "users", "email", nil)
	must(err)
	fmt.Println("plaintext  :", string(pt))

	// ─────────────────────────────────────────────────────────────────────────
	fmt.Println("\n── 2. Blind index (fast — matches Laravel ->fast(true)) ────────")
	// ─────────────────────────────────────────────────────────────────────────

	// BlindIndexFast = BLAKE2b keyed hash
	// Matches Laravel: $attribute->index('email_index', fn(Index $i) => $i->bits(256)->fast(true))
	idx, err := eng.BlindIndexFast("alice@example.com", "users", "email", "email_index", 256)
	must(err)
	fmt.Println("email_index:", idx)
	fmt.Println("SQL query  : SELECT * FROM users WHERE email_index = ?")

	// ─────────────────────────────────────────────────────────────────────────
	fmt.Println("\n── 3. EncryptedField (higher-level API) ────────────────────────")
	// ─────────────────────────────────────────────────────────────────────────

	emailField := field.New(eng, "users", "email").
		AddBlindIndex(blindindex.New("email_index",
			blindindex.WithBits(256),
			blindindex.WithFast(), // matches Laravel ->fast(true)
		))

	ciphertext, indexes, err := emailField.PrepareForStorage("alice@example.com")
	must(err)
	fmt.Println("ciphertext        :", ciphertext)
	fmt.Println("email_index       :", indexes["email_index"])

	plain, err := emailField.Decrypt(ciphertext)
	must(err)
	fmt.Println("decrypted         :", plain)

	// Search
	searchIdx, err := emailField.GetBlindIndex("alice@example.com", "email_index")
	must(err)
	fmt.Println("search index      :", searchIdx)
	fmt.Println("matches stored    :", searchIdx == indexes["email_index"])

	// ─────────────────────────────────────────────────────────────────────────
	fmt.Println("\n── 4. EncryptedRow (multiple fields at once) ───────────────────")
	// ─────────────────────────────────────────────────────────────────────────

	userRow := row.New(eng, "users").
		AddField("email").
		AddField("phone").
		AddField("nisn").
		AddBlindIndex("email", blindindex.New("email_index",
			blindindex.WithBits(256),
			blindindex.WithFast(),
		)).
		AddBlindIndex("phone", blindindex.New("phone_index",
			blindindex.WithBits(256),
			blindindex.WithFast(),
		)).
		AddBlindIndex("nisn", blindindex.New("nisn_index",
			blindindex.WithBits(256),
			blindindex.WithFast(),
		))

	encrypted, idxMap, err := userRow.PrepareForStorage(row.RowData{
		"email": "alice@example.com",
		"phone": "+6281234567890",
		"nisn":  "1234567890",
	})
	must(err)

	fmt.Println("encrypted email   :", encrypted["email"][:30]+"…")
	fmt.Println("encrypted phone   :", encrypted["phone"][:30]+"…")
	fmt.Println("email_index       :", idxMap["email_index"])
	fmt.Println("phone_index       :", idxMap["phone_index"])
	fmt.Println("nisn_index        :", idxMap["nisn_index"])

	decrypted, err := userRow.DecryptRow(encrypted)
	must(err)
	fmt.Println("decrypted email   :", decrypted["email"])
	fmt.Println("decrypted phone   :", decrypted["phone"])

	// ─────────────────────────────────────────────────────────────────────────
	fmt.Println("\n── 5. Decrypt a ciphertext from Laravel ────────────────────────")
	// ─────────────────────────────────────────────────────────────────────────
	// Use the same key as CIPHERSWEET_KEY in your Laravel .env.
	// Ciphertexts produced by Laravel decrypt transparently here.
	//
	// Example (replace with a real ciphertext from your DB):
	//   laravelCT := "nacl:QTQUYxsG..."
	//   pt, err := eng.DecryptField(laravelCT, "users", "email", nil)
	fmt.Println("(replace laravelCT with a real ciphertext from your DB)")

	// ─────────────────────────────────────────────────────────────────────────
	fmt.Println("\n── 6. Key providers ────────────────────────────────────────────")
	// ─────────────────────────────────────────────────────────────────────────

	// From environment variable (recommended for production)
	_ = keyprovider.NewEnvProvider("CIPHERSWEET_KEY")

	// From a file (Docker secrets / Kubernetes secret mounts)
	_ = keyprovider.NewFileProvider("/run/secrets/ciphersweet_key")

	// Generate a random key (tests only — lost on process restart)
	rp, err := keyprovider.NewRandomProvider()
	must(err)
	fmt.Println("random key (tests only):", rp.HexString())
	fmt.Println("set in .env: CIPHERSWEET_KEY=" + rp.HexString())
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
