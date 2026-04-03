# ciphersweet-go

> [!TIP]
> **Laravel Interoperability:** When table names, field names, key material, and blind-index options are configured identically, this Go library's ciphertext and blind indexes are fully compatible with Laravel’s [magentron/ciphersweet-for-laravel](https://github.com/magentron/ciphersweet-for-laravel) and [bjornvoesten/ciphersweet](https://github.com/bjornvoesten/ciphersweet).

A Go library for **searchable encrypted columns**. It allows you to securely store encrypted data in your database while still being able to perform exact-match lookups using **blind indexes**. Based on the original PHP [paragonie/ciphersweet](https://github.com/paragonie/ciphersweet).

### How it works

When you encrypt a column (e.g., `email`), you also create a "blind index" companion column (e.g., `email_index`). 

1. **Saving**: The app encrypts the `email` before saving it. It also generates a consistent, one-way hash (the "blind index") from the email and saves it to `email_index`.
2. **Searching**: To search by email, the app generates the same hash for the search term and looks up `email_index = ?`.
3. **Reading**: When retrieving a row, the app automatically decrypts the `email` column back to plain text.

---

## Installation

```bash
go get github.com/rizalpahlevii/ciphersweet-go
```

---

## Quick Start (with GORM)

The easiest way to integrate CipherSweet is using our GORM package via struct tags.

### 1. Initialize the Engine
You need a 256-bit hex key (generate one with `openssl rand -hex 32`). Load this key into the CipherSweet engine.

```go
import (
	"github.com/rizalpahlevii/ciphersweet-go/backend"
	"github.com/rizalpahlevii/ciphersweet-go/engine"
	"github.com/rizalpahlevii/ciphersweet-go/keyprovider"
	gormcrypt "github.com/rizalpahlevii/ciphersweet-go/gorm"
)

// 1. Setup the key provider (reads CIPHERSWEET_KEY from env)
kp := keyprovider.NewEnvProvider("CIPHERSWEET_KEY") 

// 2. Initialize the engine
eng, _ := engine.New(backend.NewNaCl(), kp)

// 3. Register GORM hooks
gormcrypt.Setup(eng)
gormcrypt.RegisterTagCallbacks(db) // 'db' is your *gorm.DB instance
```

### 2. Define Your Model
Add the `gormcrypt` tag to any string fields you want to encrypt. You must also declare a field to store the blind index.

```go
type User struct {
    gorm.Model
    Name       string
    
    // The `Email` field will be encrypted. 
    // `EmailIndex` will store the searchable hash.
    Email      string `gormcrypt:"blind_index=email_index"`
    EmailIndex string 
    
    // You can customize index behavior (e.g., fast hashing, 256-bit width)
    Nisn       string `gormcrypt:"blind_index=nisn_index,fast=true,bits=256"`
    NisnIndex  string
}
```

### 3. Querying Encrypted Data
Use `gormcrypt.WhereTag` to search for exact matches on encrypted columns.

```go
var users []User

// Search by a single encrypted field
db.Scopes(gormcrypt.WhereTag(&User{}, "email", "alice@example.com")).Find(&users)

// Search by multiple encrypted fields
db.Scopes(gormcrypt.WhereTagMulti(&User{},
    "email", "alice@example.com",
    "nisn", "1234567890",
)).Find(&users)
```

> [!NOTE]
> GORM's `Create` hooks work seamlessly. Just remember that after a `Create` operation, the tagged struct values will hold the *encrypted* string. If you need the plaintext right away, call `gormcrypt.DecryptTagged(&user)` in your `AfterCreate` hook.

---

## Manual Usage (Without GORM)

You can manage encryption manually if you aren't using GORM.

### Single Encrypted Field

```go
import (
    "github.com/rizalpahlevii/ciphersweet-go/field"
    "github.com/rizalpahlevii/ciphersweet-go/blindindex"
    "github.com/rizalpahlevii/ciphersweet-go/blindindex/transform"
)

// Define the encrypted field configuration
emailField := field.New(eng, "users", "email").
    AddBlindIndex(blindindex.New("email_index",
        blindindex.WithBits(256),
        blindindex.WithFast(),
        blindindex.WithTransform(transform.Lowercase{}), // e.g., Alice@Example.com -> alice@example.com
    ))

// 1. Encrypt for saving
ciphertext, indexes, _ := emailField.PrepareForStorage("alice@example.com")
// > Save `ciphertext` to DB column `email` 
// > Save `indexes["email_index"]` to DB column `email_index`

// 2. Decrypt after reading from database
plaintext, _ := emailField.Decrypt(ciphertext)

// 3. Generate index for searching
searchHash, _ := emailField.GetBlindIndex("alice@example.com", "email_index")
// > SELECT * FROM users WHERE email_index = ? (pass searchHash)
```

### Multiple Fields (Row Encryption)

Encrypting multiple columns for a single row simultaneously:

```go
import (
    "github.com/rizalpahlevii/ciphersweet-go/row"
    "github.com/rizalpahlevii/ciphersweet-go/blindindex"
)

userRow := row.New(eng, "users").
    AddField("email").AddField("phone").
    AddBlindIndex("email", blindindex.New("email_index", blindindex.WithBits(256), blindindex.WithFast())).
    AddBlindIndex("phone", blindindex.New("phone_index", blindindex.WithBits(256), blindindex.WithFast()))

// Encrypt multiple values at once
encryptedMap, indexMap, _ := userRow.PrepareForStorage(map[string]string{
    "email": "alice@example.com",
    "phone": "+15551234567",
})

// Decrypt row data
plaintextMap, _ := userRow.DecryptRow(encryptedMap)

// Generate search index for a specific field
idx, _ := userRow.GetBlindIndex("email", "alice@example.com", "email_index")
```

---

## Advanced Configuration

### Key Providers

Different ways to load your master encryption key:

| Provider | Description |
| :--- | :--- |
| `NewEnvProvider("")` | Reads from `CIPHERSWEET_KEY` environment variable. |
| `NewEnvProvider("MY_VAR")` | Reads from a custom env var name. |
| `NewFileProvider(path)` | Reads from a secret file (e.g., Docker / Kubernetes secrets). |
| `NewStringProvider(hex)` | Hardcoded key string (Not recommended for production). |
| `MustRandomProvider()` | Generates a random key for testing purposes. |

### Blind Indexes Options

- **Fast (Default)** — Uses `BLAKE2b`. Fast and best for web application indexes. Enable with `WithFast()`.
- **Slow** — Uses `Argon2id`. Slower but harder to brute-force if your DB is compromised. Simply omit `WithFast()`.

**Index Size Recommendations:**

| Database Rows | Bits | Suggested Column Type |
| :--- | :--- | :--- |
| < 1,000 | 16 | `VARCHAR(4)` |
| < 1 Million | 32 | `VARCHAR(8)` |
| Large Datasets | 64 - 256 | Wider `VARCHAR` |

**Data Transformers** (`blindindex/transform`):
Change the data *before* creating the hash to support case-insensitive or partial searches.
- `Lowercase`: Ideal for emails.
- `DigitsOnly`: Good for phone numbers.
- `LastFourDigits`: Good for SSN or Credit Card search.

### Database Migrations

Generate DDL statements for encrypted columns easily:

```go
import "github.com/rizalpahlevii/ciphersweet-go/migrate"

sql := migrate.NewPlan("users").
    AddEncryptedColumn("email").
    AddIndexColumn("email_index", migrate.IndexWidth256).
    WithDialect(migrate.MySQL). // migrate.MySQL, migrate.PostgreSQL, migrate.SQLite
    Up()
```

---

## Testing Your Code

The library comes with a `testing` package to verify your integration quickly.

```go
import cstesting "github.com/rizalpahlevii/ciphersweet-go/cstesting"

func TestEmailField(t *testing.T) {
    ef := cstesting.EmailField(t) // Provides a configured dummy field
    
    ct, indexes, err := ef.PrepareForStorage("alice@example.com")
    cstesting.NoError(t, err)
    
    // Check decryption
    cstesting.AssertDecrypts(t, ef, ct, "alice@example.com")
    
    // Check searchability
    cstesting.AssertIndexSearchable(t, ef, "alice@example.com", "email_index", indexes)
}
```

> [!TIP]
> **Runnable Example:** We also have a fully runnable example combining gorm, sqlite, and ciphersweet in the [`example/`](./example/) directory. Feel free to clone the repo and run `go run example/main.go` to see it in action.

---

## Security

> [!IMPORTANT]
> **Data Integrity:** CipherSweet provides authenticated encryption. Any tampering with the ciphertext in the database will cause decryption to fail, preventing attackers from subtly modifying data.
>
> **Key Isolation:** Field keys are derived using HKDF based on the table name and field name. Blind index keys use an entirely separate derivation domain.
>
> **One-Way Hashes:** Blind indexes are deterministic hashes; they cannot be reversed to reveal the plaintext. However, they do leak whether two rows have the exact same value.

---

## License

MIT License