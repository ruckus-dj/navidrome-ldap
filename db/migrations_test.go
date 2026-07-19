package db

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pressly/goose/v3"
)

func TestApplyMigrationsAppliesMissingVersions(t *testing.T) {
	migrations, err := goose.CollectMigrations("migrations", 0, math.MaxInt64)
	if err != nil {
		t.Fatalf("collect registered migrations: %v", err)
	}
	var registeredGoMigrations []*goose.Migration
	for _, migration := range migrations {
		if migration.Type == goose.TypeGo {
			registeredGoMigrations = append(registeredGoMigrations, migration)
		}
	}
	goose.ResetGlobalMigrations()
	t.Cleanup(func() {
		goose.ResetGlobalMigrations()
		if err := goose.SetGlobalMigrations(registeredGoMigrations...); err != nil {
			t.Errorf("restore registered migrations: %v", err)
		}
	})

	root := t.TempDir()
	migrationsDir := filepath.Join(root, "migrations")
	if err := os.Mkdir(migrationsDir, 0o755); err != nil {
		t.Fatalf("create migrations directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(migrationsDir, "20260714123822_upstream.sql"), []byte("-- +goose Up\nCREATE TABLE upstream_marker (id INTEGER);\n-- +goose Down\nDROP TABLE upstream_marker;\n"), 0o600); err != nil {
		t.Fatalf("write upstream migration: %v", err)
	}

	database, err := sql.Open(Dialect, "file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })

	goose.SetBaseFS(os.DirFS(root))
	t.Cleanup(func() { goose.SetBaseFS(os.DirFS(".")) })
	if err := goose.SetDialect(Dialect); err != nil {
		t.Fatalf("set goose dialect: %v", err)
	}
	if err := goose.UpContext(context.Background(), database, "migrations"); err != nil {
		t.Fatalf("apply upstream migration: %v", err)
	}

	if err := os.WriteFile(filepath.Join(migrationsDir, "20260427000000_add_user_app_password.sql"), []byte("-- +goose Up\nCREATE TABLE user_app_password (id INTEGER);\n-- +goose Down\nDROP TABLE user_app_password;\n"), 0o600); err != nil {
		t.Fatalf("write app-password migration: %v", err)
	}
	if err := os.WriteFile(filepath.Join(migrationsDir, "20260430000000_add_user_auth_type.sql"), []byte("-- +goose Up\nCREATE TABLE user_auth_type (id INTEGER);\n-- +goose Down\nDROP TABLE user_auth_type;\n"), 0o600); err != nil {
		t.Fatalf("write auth-type migration: %v", err)
	}
	unexpectedMigration := filepath.Join(migrationsDir, "20260428000000_unexpected_backfill.sql")
	if err := os.WriteFile(unexpectedMigration, []byte("-- +goose Up\nCREATE TABLE unexpected_backfill (id INTEGER);\n-- +goose Down\nDROP TABLE unexpected_backfill;\n"), 0o600); err != nil {
		t.Fatalf("write unexpected migration: %v", err)
	}

	err = applyMigrations(context.Background(), database, "migrations")
	if err == nil {
		t.Fatal("apply unexpected missing migration: expected an error")
	}
	if !strings.Contains(err.Error(), "20260428000000") {
		t.Fatalf("apply unexpected missing migration: %v", err)
	}
	for _, table := range []string{"user_app_password", "user_auth_type", "unexpected_backfill"} {
		var name string
		err := database.QueryRow("SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?", table).Scan(&name)
		if !errors.Is(err, sql.ErrNoRows) {
			t.Fatalf("bridge migration %q ran before rejection: %v", table, err)
		}
	}

	if err := os.Remove(unexpectedMigration); err != nil {
		t.Fatalf("remove unexpected migration: %v", err)
	}
	if err := applyMigrations(context.Background(), database, "migrations"); err != nil {
		t.Fatalf("apply known LDAP migrations: %v", err)
	}
	for _, table := range []string{"user_app_password", "user_auth_type"} {
		var name string
		if err := database.QueryRow("SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?", table).Scan(&name); err != nil {
			t.Fatalf("known LDAP migration %q was not applied: %v", table, err)
		}
	}

	restartUnexpectedMigration := filepath.Join(migrationsDir, "20260501000000_restart_backfill.sql")
	if err := os.WriteFile(restartUnexpectedMigration, []byte("-- +goose Up\nCREATE TABLE restart_backfill (id INTEGER);\n-- +goose Down\nDROP TABLE restart_backfill;\n"), 0o600); err != nil {
		t.Fatalf("write restart migration: %v", err)
	}
	err = applyMigrations(context.Background(), database, "migrations")
	if err == nil {
		t.Fatal("apply restart migration: expected an error")
	}
	if !strings.Contains(err.Error(), "20260501000000") {
		t.Fatalf("apply restart migration: %v", err)
	}
	var name string
	err = database.QueryRow("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'restart_backfill'").Scan(&name)
	if !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("restart migration ran before rejection: %v", err)
	}
}

func TestApplyMigrationsBackfillsLDAPSchema(t *testing.T) {
	database, err := sql.Open(Dialect, "file:ldap-bridge-actual?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })

	goose.SetBaseFS(os.DirFS("."))
	if err := goose.SetDialect(Dialect); err != nil {
		t.Fatalf("set goose dialect: %v", err)
	}
	if err := goose.UpContext(context.Background(), database, "migrations"); err != nil {
		t.Fatalf("apply current migrations: %v", err)
	}
	if _, err := database.Exec(`DROP TABLE user_app_password`); err != nil {
		t.Fatalf("drop app-password table: %v", err)
	}
	if _, err := database.Exec(`DROP INDEX idx_user_auth_type`); err != nil {
		t.Fatalf("drop auth-type index: %v", err)
	}
	if _, err := database.Exec(`ALTER TABLE user DROP COLUMN auth_type`); err != nil {
		t.Fatalf("drop auth-type column: %v", err)
	}
	if _, err := database.Exec(`DELETE FROM goose_db_version WHERE version_id IN (?, ?)`, ldapAppPasswordMigrationVersion, ldapAuthTypeMigrationVersion); err != nil {
		t.Fatalf("remove LDAP migration records: %v", err)
	}

	if err := applyMigrations(context.Background(), database, "migrations"); err != nil {
		t.Fatalf("backfill LDAP schema: %v", err)
	}
	var name string
	if err := database.QueryRow("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'user_app_password'").Scan(&name); err != nil {
		t.Fatalf("query app-password table: %v", err)
	}
	if err := database.QueryRow("SELECT auth_type FROM user LIMIT 1").Scan(&name); err != nil && !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("query auth-type column: %v", err)
	}
}
