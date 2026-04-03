package migrate

import (
	"fmt"
	"strings"
)

// IndexWidth constants match common blind index bit widths → column byte lengths.
const (
	IndexWidth16  = 4  // 16-bit  → 4 hex chars
	IndexWidth32  = 8  // 32-bit  → 8 hex chars
	IndexWidth64  = 16 // 64-bit  → 16 hex chars
	IndexWidth128 = 32 // 128-bit → 32 hex chars
	IndexWidth256 = 64 // 256-bit → 64 hex chars (default)
)

// Dialect controls DDL syntax differences between databases.
type Dialect int

const (
	MySQL      Dialect = iota // MySQL / MariaDB / PlanetScale
	PostgreSQL                // PostgreSQL / CockroachDB
	SQLite                    // SQLite
)

type colDef struct {
	name       string
	colType    string // "encrypted" | "index"
	charLength int    // for index columns
}

// Plan is a migration plan for one table.
type Plan struct {
	table   string
	dialect Dialect
	cols    []colDef
}

// NewPlan creates a migration plan for the given table using MySQL syntax.
func NewPlan(table string) *Plan {
	return &Plan{table: table, dialect: MySQL}
}

// WithDialect sets the SQL dialect.
func (p *Plan) WithDialect(d Dialect) *Plan {
	p.dialect = d
	return p
}

// AddEncryptedColumn adds a TEXT column to hold a ciphertext.
func (p *Plan) AddEncryptedColumn(name string) *Plan {
	p.cols = append(p.cols, colDef{name: name, colType: "encrypted"})
	return p
}

// AddIndexColumn adds a VARCHAR column and a DB index for a blind index.
// charLength should be one of the IndexWidthXX constants or a custom value.
func (p *Plan) AddIndexColumn(name string, charLength int) *Plan {
	p.cols = append(p.cols, colDef{name: name, colType: "index", charLength: charLength})
	return p
}

// Up returns the SQL to add all columns and indexes to the table.
func (p *Plan) Up() string {
	var sb strings.Builder
	for _, col := range p.cols {
		switch col.colType {
		case "encrypted":
			sb.WriteString(p.addEncryptedCol(col.name))
		case "index":
			sb.WriteString(p.addIndexCol(col.name, col.charLength))
			sb.WriteString(p.addDBIndex(col.name))
		}
	}
	return sb.String()
}

// Down returns the SQL to remove all columns added by Up.
func (p *Plan) Down() string {
	var sb strings.Builder
	// Drop in reverse order.
	for i := len(p.cols) - 1; i >= 0; i-- {
		col := p.cols[i]
		if col.colType == "index" {
			sb.WriteString(p.dropDBIndex(col.name))
		}
		sb.WriteString(p.dropCol(col.name))
	}
	return sb.String()
}

// CreateTable returns a minimal CREATE TABLE statement with id + timestamps +
// all registered encrypted/index columns.  Useful for generating a fresh migration.
func (p *Plan) CreateTable() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s (\n", p.quote(p.table)))

	switch p.dialect {
	case PostgreSQL:
		sb.WriteString("    id BIGSERIAL PRIMARY KEY,\n")
	default:
		sb.WriteString("    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,\n")
	}

	for _, col := range p.cols {
		switch col.colType {
		case "encrypted":
			sb.WriteString(fmt.Sprintf("    %s TEXT NULL,\n", p.quote(col.name)))
		case "index":
			sb.WriteString(fmt.Sprintf("    %s VARCHAR(%d) NULL,\n", p.quote(col.name), col.charLength))
		}
	}

	switch p.dialect {
	case PostgreSQL:
		sb.WriteString("    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),\n")
		sb.WriteString("    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()\n")
	default:
		sb.WriteString("    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,\n")
		sb.WriteString("    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP\n")
	}

	sb.WriteString(");\n")

	// Add indexes.
	for _, col := range p.cols {
		if col.colType == "index" {
			sb.WriteString(p.addDBIndex(col.name))
		}
	}
	return sb.String()
}

// ─── Internal DDL builders ────────────────────────────────────────────────────

func (p *Plan) addEncryptedCol(name string) string {
	return fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s TEXT NULL;\n",
		p.quote(p.table), p.quote(name))
}

func (p *Plan) addIndexCol(name string, length int) string {
	return fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s VARCHAR(%d) NULL;\n",
		p.quote(p.table), p.quote(name), length)
}

func (p *Plan) addDBIndex(name string) string {
	idxName := fmt.Sprintf("idx_%s_%s", p.table, name)
	switch p.dialect {
	case PostgreSQL:
		return fmt.Sprintf("CREATE INDEX IF NOT EXISTS %s ON %s (%s);\n",
			idxName, p.quote(p.table), p.quote(name))
	default:
		return fmt.Sprintf("CREATE INDEX %s ON %s (%s);\n",
			idxName, p.quote(p.table), p.quote(name))
	}
}

func (p *Plan) dropDBIndex(name string) string {
	idxName := fmt.Sprintf("idx_%s_%s", p.table, name)
	switch p.dialect {
	case PostgreSQL:
		return fmt.Sprintf("DROP INDEX IF EXISTS %s;\n", idxName)
	default:
		return fmt.Sprintf("DROP INDEX %s ON %s;\n", idxName, p.quote(p.table))
	}
}

func (p *Plan) dropCol(name string) string {
	return fmt.Sprintf("ALTER TABLE %s DROP COLUMN %s;\n",
		p.quote(p.table), p.quote(name))
}

func (p *Plan) quote(name string) string {
	switch p.dialect {
	case PostgreSQL:
		return `"` + name + `"`
	default:
		return "`" + name + "`"
	}
}
