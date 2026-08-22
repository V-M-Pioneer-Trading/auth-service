package db

import (
	"database/sql"
	_ "embed"
	"log"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schema string

// getEnv mirrors agent-service's db.go helper.
func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// SetUpDatabase opens (creating if needed) the SQLite file at SQLITE_DB_PATH
// and applies the idempotent schema. One connection only — SQLite doesn't
// cope well with concurrent writers, same reasoning as navigation-service's
// application.properties pool-size-1 setting.
func SetUpDatabase() *sql.DB {
	path := getEnv("SQLITE_DB_PATH", "./data/auth.db")

	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			log.Fatal(err)
		}
	}

	conn, err := sql.Open("sqlite", path)
	if err != nil {
		log.Fatal(err)
	}
	conn.SetMaxOpenConns(1)

	if _, err := conn.Exec(schema); err != nil {
		log.Fatal(err)
	}
	log.Default().Printf("Schema migrations applied to %s.", path)

	return conn
}

// OpenInMemory opens a fresh :memory: SQLite database with the schema
// applied. Used by other packages' tests so the schema stays defined in one
// place instead of copy-pasted per test file.
func OpenInMemory() (*sql.DB, error) {
	conn, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return nil, err
	}
	conn.SetMaxOpenConns(1)
	if _, err := conn.Exec(schema); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}
