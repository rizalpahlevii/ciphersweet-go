package migrate

import (
	"strings"
	"testing"
)

func TestPlan_Up_MySQL(t *testing.T) {
	plan := NewPlan("users").
		AddEncryptedColumn("email").
		AddIndexColumn("email_index", IndexWidth256).
		WithDialect(MySQL)

	sql := plan.Up()

	expectedEncrypted := "ALTER TABLE `users` ADD COLUMN `email` TEXT NULL;"
	if !strings.Contains(sql, expectedEncrypted) {
		t.Errorf("Expected SQL to contain %q, got: %s", expectedEncrypted, sql)
	}

	expectedIndexCol := "ALTER TABLE `users` ADD COLUMN `email_index` VARCHAR(64) NULL;"
	if !strings.Contains(sql, expectedIndexCol) {
		t.Errorf("Expected SQL to contain %q, got: %s", expectedIndexCol, sql)
	}

	expectedIndex := "CREATE INDEX idx_users_email_index ON `users` (`email_index`);"
	if !strings.Contains(sql, expectedIndex) {
		t.Errorf("Expected SQL to contain %q, got: %s", expectedIndex, sql)
	}
}

func TestPlan_Down_MySQL(t *testing.T) {
	plan := NewPlan("users").
		AddEncryptedColumn("email").
		AddIndexColumn("email_index", IndexWidth256).
		WithDialect(MySQL)

	sql := plan.Down()

	expectedDropIndex := "DROP INDEX idx_users_email_index ON `users`;"
	if !strings.Contains(sql, expectedDropIndex) {
		t.Errorf("Expected SQL to contain %q, got: %s", expectedDropIndex, sql)
	}

	expectedDropIndexCol := "ALTER TABLE `users` DROP COLUMN `email_index`;"
	if !strings.Contains(sql, expectedDropIndexCol) {
		t.Errorf("Expected SQL to contain %q, got: %s", expectedDropIndexCol, sql)
	}

	expectedDropEncryptedCol := "ALTER TABLE `users` DROP COLUMN `email`;"
	if !strings.Contains(sql, expectedDropEncryptedCol) {
		t.Errorf("Expected SQL to contain %q, got: %s", expectedDropEncryptedCol, sql)
	}

	// Should drop index before dropping the column. The index drop should appear first.
	indexIdx := strings.Index(sql, expectedDropIndex)
	colIdx := strings.Index(sql, expectedDropIndexCol)
	if indexIdx > colIdx {
		t.Errorf("Expected index drop to occur before column drop")
	}
}

func TestPlan_CreateTable_PostgreSQL(t *testing.T) {
	plan := NewPlan("users").
		AddEncryptedColumn("email").
		AddIndexColumn("email_index", IndexWidth256).
		WithDialect(PostgreSQL)

	sql := plan.CreateTable()

	expectedID := "id BIGSERIAL PRIMARY KEY"
	if !strings.Contains(sql, expectedID) {
		t.Errorf("Expected SQL to contain %q, got: %s", expectedID, sql)
	}

	expectedEmail := "\"email\" TEXT NULL"
	if !strings.Contains(sql, expectedEmail) {
		t.Errorf("Expected SQL to contain %q, got: %s", expectedEmail, sql)
	}

	expectedEmailIndex := "\"email_index\" VARCHAR(64) NULL"
	if !strings.Contains(sql, expectedEmailIndex) {
		t.Errorf("Expected SQL to contain %q, got: %s", expectedEmailIndex, sql)
	}

	expectedTimestamps := "updated_at TIMESTAMPTZ"
	if !strings.Contains(sql, expectedTimestamps) {
		t.Errorf("Expected SQL to contain %q, got: %s", expectedTimestamps, sql)
	}

	expectedIdx := "CREATE INDEX IF NOT EXISTS idx_users_email_index ON \"users\" (\"email_index\");"
	if !strings.Contains(sql, expectedIdx) {
		t.Errorf("Expected SQL to contain %q, got: %s", expectedIdx, sql)
	}
}

func TestPlan_Down_PostgreSQL(t *testing.T) {
	plan := NewPlan("users").
		AddIndexColumn("email_index", IndexWidth16).
		WithDialect(PostgreSQL)

	sql := plan.Down()

	expectedDropIndex := "DROP INDEX IF EXISTS idx_users_email_index;"
	if !strings.Contains(sql, expectedDropIndex) {
		t.Errorf("Expected SQL to contain %q, got: %s", expectedDropIndex, sql)
	}
}
