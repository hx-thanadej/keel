// Package storetest gives each test a fresh, migrated Keel database, accessed
// through the real application role so row-level security is exercised.
package storetest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"os"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hx-thanadej/keel/internal/store"
)

// EnvURL names the env var holding an admin connection URL to a disposable
// Postgres server, e.g. postgres://postgres:postgres@localhost:5432/postgres.
const EnvURL = "KEEL_TEST_DATABASE_URL"

const (
	ownerRole = "keel_owner"
	appRole   = "keel_app"
	password  = "keel-test-only"
)

// New creates a database owned by keel_owner, migrates it, and returns a Store
// connected as keel_app. Skips the test if EnvURL is unset.
func New(t *testing.T) *store.Store {
	t.Helper()
	adminURL := os.Getenv(EnvURL)
	if adminURL == "" {
		t.Skipf("%s not set; skipping database test", EnvURL)
	}
	ctx := context.Background()

	admin, err := pgx.Connect(ctx, adminURL)
	if err != nil {
		t.Fatalf("connect admin: %v", err)
	}
	defer func() { _ = admin.Close(ctx) }()

	// Roles are cluster-wide; create once, reuse across tests. Mirrors db/roles.sql.
	for _, stmt := range []string{
		`DO $$ BEGIN
		   IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '` + ownerRole + `') THEN
		     CREATE ROLE ` + ownerRole + ` LOGIN PASSWORD '` + password + `';
		   END IF;
		   IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '` + appRole + `') THEN
		     CREATE ROLE ` + appRole + ` LOGIN PASSWORD '` + password + `' NOSUPERUSER NOBYPASSRLS;
		   END IF;
		   IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'keel_lookup') THEN
		     CREATE ROLE keel_lookup NOLOGIN BYPASSRLS;
		   END IF;
		   GRANT keel_lookup TO ` + ownerRole + `;
		 END $$`,
	} {
		if _, err := admin.Exec(ctx, stmt); err != nil && !isDuplicateRole(err) {
			t.Fatalf("bootstrap roles: %v", err)
		}
	}

	dbName := "keel_test_" + randomHex(t)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+dbName+" OWNER "+ownerRole); err != nil {
		t.Fatalf("create database: %v", err)
	}
	t.Cleanup(func() {
		c, err := pgx.Connect(context.Background(), adminURL)
		if err != nil {
			t.Logf("cleanup connect: %v", err)
			return
		}
		defer func() { _ = c.Close(context.Background()) }()
		if _, err := c.Exec(context.Background(), "DROP DATABASE IF EXISTS "+dbName+" WITH (FORCE)"); err != nil {
			t.Logf("drop %s: %v", dbName, err)
		}
	})

	if err := store.Migrate(ctx, withUser(t, adminURL, ownerRole, dbName)); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	pool, err := pgxpool.New(ctx, withUser(t, adminURL, appRole, dbName))
	if err != nil {
		t.Fatalf("app pool: %v", err)
	}
	t.Cleanup(pool.Close)
	s := store.New(pool)
	superURLs.Store(s, superURL(t, adminURL, dbName))
	return s
}

var superURLs sync.Map // *store.Store → superuser URL of its database

// Superuser connects to s's database as the admin (superuser) role, to
// simulate an attacker with full database access. Tests only.
func Superuser(t *testing.T, s *store.Store) *pgx.Conn {
	t.Helper()
	u, ok := superURLs.Load(s)
	if !ok {
		t.Fatal("store not created by storetest.New")
	}
	c, err := pgx.Connect(context.Background(), u.(string))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	return c
}

func superURL(t *testing.T, base, db string) string {
	t.Helper()
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + db
	return u.String()
}

func withUser(t *testing.T, base, user, db string) string {
	t.Helper()
	u, err := url.Parse(base)
	if err != nil {
		t.Fatalf("parse %s: %v", EnvURL, err)
	}
	u.User = url.UserPassword(user, password)
	u.Path = "/" + db
	return u.String()
}

func randomHex(t *testing.T) string {
	t.Helper()
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// Concurrent tests can race on CREATE ROLE despite IF NOT EXISTS.
func isDuplicateRole(err error) bool {
	return err != nil && (contains(err.Error(), "already exists") || contains(err.Error(), "23505"))
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
