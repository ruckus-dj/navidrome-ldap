package db

import (
	"context"
	"database/sql"
	"math"
	"os"
	"path/filepath"
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
		t.Fatalf("write LDAP migration: %v", err)
	}

	if err := applyMigrations(context.Background(), database, "migrations"); err != nil {
		t.Fatalf("apply missing LDAP migration: %v", err)
	}

	var name string
	if err := database.QueryRow("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'user_app_password'").Scan(&name); err != nil {
		t.Fatalf("query LDAP migration result: %v", err)
	}
}
