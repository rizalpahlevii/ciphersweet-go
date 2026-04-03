// Package migrate provides SQL migration helpers for CipherSweet.
//
// # Overview
//
// This package generates the SQL statements needed to add encrypted field
// columns and their blind index columns. It is intended to be used with a
// migration tool; it outputs SQL strings rather than executing them.
//
// Key Concepts / Features
//
//   - Plan builds a sequence of DDL statements for one table.
//   - AddEncryptedColumn adds a TEXT column for ciphertext values.
//   - AddIndexColumn adds a VARCHAR column plus a DB index for blind index
//     equality queries.
//   - Dialect selects SQL syntax differences.
//
// Example:
//
//	plan := migrate.NewPlan("users").
//	    AddEncryptedColumn("email").
//	    AddIndexColumn("email_index", migrate.IndexWidth256).
//	    AddEncryptedColumn("phone").
//	    AddIndexColumn("phone_index", migrate.IndexWidth256)
//
//	fmt.Println(plan.Up())   // add columns + indexes
//	fmt.Println(plan.Down()) // remove columns + indexes
//
// Architecture / Design
//
// DDL builders in Plan are database-agnostic string generators. They do not
// introspect the current schema.
//
// # Security Notes
//
// This package does not perform encryption. It only generates schema
// statements for use with encrypted values produced by other packages.
//
// # Compatibility
//
// Index column widths match common blind index bit widths (for example,
// IndexWidth256 maps to the expected hex string length for a 256-bit index).
//
// # Project Information
//
// Package name: migrate
// Project description: SQL DDL generators for encrypted fields and blind indexes.
// Key features:
//   - Plan builder for Up/Down DDL
//   - Dialect support for MySQL, PostgreSQL, SQLite
//   - IndexWidth helpers for VARCHAR sizes
//
// Example usage: migrate.NewPlan(...).AddEncryptedColumn(...).Up()
// Special notes: The output is meant to be piped into your migration tool.
package migrate
