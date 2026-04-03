// Package gormcrypt integrates CipherSweet with GORM using struct tags.
//
// Declare encrypted string fields and blind-index columns with `gormcrypt`,
// call Setup and RegisterTagCallbacks once at startup, then use WhereTag,
// WhereTagMulti, or TagIndex for queries. Use SetTableName when the database
// table name is not the default snake_case plural of the struct name.
//
// For custom blind-index transforms or layouts that tags cannot express, build
// *row.EncryptedRow in the row package and call it from your own GORM hooks;
// gormcrypt only automates the tag-driven path.
//
// Startup:
//
//	gormcrypt.Setup(eng)
//	gormcrypt.RegisterTagCallbacks(db)
//
// Model (DB column for the tag holds ciphertext; companion field holds the index):
//
//	type User struct {
//	    gorm.Model
//	    Name       string
//	    Email      string `gormcrypt:"blind_index=email_index"`
//	    EmailIndex string
//	    Phone      string `gormcrypt:"blind_index=phone_index"`
//	    PhoneIndex string
//	    Nisn       string `gormcrypt:"blind_index=nisn_index,fast=true,bits=256"`
//	    NisnIndex  string
//	}
//
// Tag options: comma-separated key=value. blind_index is required; fast defaults
// true; bits defaults 256.
//
// Search:
//
//	db.Scopes(gormcrypt.WhereTag(&User{}, "email", "alice@example.com")).Find(&users)
//
//	db.Scopes(gormcrypt.WhereTagMulti(&User{},
//	    "email", "alice@example.com",
//	    "phone", "+6281234567890",
//	)).Find(&users)
//
// Thinner call sites:
//
//	func WhereNisn(value string) func(*gorm.DB) *gorm.DB {
//	    return gormcrypt.WhereTag(&User{}, "nisn", value)
//	}
//
// # Security
//
// CipherSweet encryption is authenticated; wrong keys or tampered ciphertext
// produce decryption errors.
//
// # Compatibility
//
// With the NaCl backend, ciphertexts and blind indexes align with Laravel
// CipherSweet when table names, logical field names, and blind-index options match.
//
// # Your own hooks (e.g. AfterCreate → send email)
//
// RegisterTagCallbacks only hooks Create/Update (encrypt) and Query/Row (decrypt).
// Your BeforeCreate / AfterCreate / AfterFind methods still run. After Insert,
// tagged fields in memory are ciphertext; use a copy of plaintext before Create,
// or gormcrypt.DecryptTagged(&u) inside AfterCreate for mailers, then call
// gormcrypt.EncryptTagged(&u) before any Save that must persist ciphertext again.
//
// Import: gormcrypt "github.com/rizalpahlevii/ciphersweet-go/gorm"
package gormcrypt
