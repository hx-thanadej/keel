// Package store is Keel's Postgres system of record.
//
// Tenant isolation is enforced by Postgres row-level security, not by this
// package: every Tenant-scoped query must run inside InTenant, which scopes the
// transaction to one Tenant. Queries outside it see no Tenant rows at all.
package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib" // database/sql driver for migrations
	"github.com/pressly/goose/v3"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/riverqueue/river/rivermigrate"
)

//go:embed migrations/*.sql
var migrations embed.FS

// migrationLockKey names the session advisory lock that serialises Migrate
// across keel-api replicas (ADR-0021). Advisory locks are per database.
const migrationLockKey int64 = 0x6b65656c6d6967 // "keelmig"

// migrationLockWait bounds how long Migrate waits for another replica's run.
// It leaves room for a concurrent index build on a large table.
var migrationLockWait = 15 * time.Minute

// Migrate applies all pending migrations: goose's, River's, and River's
// grants. ownerURL must connect as the role that owns the schema (never the
// application role). Replicas starting together run it one at a time: each
// holds a session advisory lock on a dedicated connection for the whole run,
// so ownerURL must reach Postgres directly, not through a transaction pooler.
// That connection sits idle outside any transaction, so CREATE INDEX
// CONCURRENTLY in a NO TRANSACTION migration does not wait on it.
func Migrate(ctx context.Context, ownerURL string) error {
	lock, err := pgx.Connect(ctx, ownerURL)
	if err != nil {
		return fmt.Errorf("migration lock: %w", err)
	}
	defer func() { _ = lock.Close(context.Background()) }()
	if _, err := lock.Exec(ctx, fmt.Sprintf("SET lock_timeout = %d", migrationLockWait.Milliseconds())); err != nil {
		return fmt.Errorf("migration lock: %w", err)
	}
	if _, err := lock.Exec(ctx, `SELECT pg_advisory_lock($1)`, migrationLockKey); err != nil {
		if pgErr := (*pgconn.PgError)(nil); errors.As(err, &pgErr) && pgErr.Code == "55P03" {
			return fmt.Errorf("migration lock not acquired within %s; another replica is still migrating: %w", migrationLockWait, err)
		}
		return fmt.Errorf("migration lock: %w", err)
	}
	return migrate(ctx, ownerURL) // closing the lock connection releases the lock
}

func migrate(ctx context.Context, ownerURL string) error {
	db, err := sql.Open("pgx", ownerURL)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer func() { _ = db.Close() }()

	provider, err := goose.NewProvider(goose.DialectPostgres, db, mustSub(migrations, "migrations"))
	if err != nil {
		return fmt.Errorf("goose: %w", err)
	}
	if _, err := provider.Up(ctx); err != nil {
		return fmt.Errorf("migrate up: %w", err)
	}
	return migrateRiver(ctx, ownerURL)
}

// migrateRiver installs River's job tables (ADR-0014) and lets the
// application role work them. River's tables hold no Tenant data, only job
// arguments naming a Tenant and a flow; the work itself runs under RLS.
func migrateRiver(ctx context.Context, ownerURL string) error {
	pool, err := pgxpool.New(ctx, ownerURL)
	if err != nil {
		return fmt.Errorf("river migrate: %w", err)
	}
	defer pool.Close()
	m, err := rivermigrate.New(riverpgxv5.New(pool), nil)
	if err != nil {
		return fmt.Errorf("river migrate: %w", err)
	}
	if _, err := m.Migrate(ctx, rivermigrate.DirectionUp, nil); err != nil {
		return fmt.Errorf("river migrate: %w", err)
	}
	_, err = pool.Exec(ctx, `DO $$ DECLARE r record; BEGIN
		FOR r IN SELECT tablename FROM pg_tables WHERE schemaname = current_schema() AND tablename LIKE 'river\_%' LOOP
			EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON %I TO keel_app', r.tablename);
		END LOOP;
		FOR r IN SELECT sequencename FROM pg_sequences WHERE schemaname = current_schema() AND sequencename LIKE 'river\_%' LOOP
			EXECUTE format('GRANT USAGE, SELECT ON SEQUENCE %I TO keel_app', r.sequencename);
		END LOOP;
	END $$`)
	if err != nil {
		return fmt.Errorf("river grants: %w", err)
	}
	return nil
}

// Store wraps a pool connected as the application role.
type Store struct {
	pool *pgxpool.Pool
}

// New wraps a pool. The pool must connect as the application role, which
// has no BYPASSRLS and owns nothing.
func New(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// AppPool exposes the raw pool for health checks and tests. Tenant data
// queried through it outside InTenant returns nothing.
func (s *Store) AppPool() *pgxpool.Pool { return s.pool }

// InTenant runs fn in a transaction scoped to tenantID. The scope is
// transaction-local, so it cannot leak to the next user of the connection.
func (s *Store) InTenant(ctx context.Context, tenantID string, fn func(pgx.Tx) error) error {
	var id pgtype.UUID
	if err := id.Scan(tenantID); err != nil {
		return fmt.Errorf("tenant id %q: %w", tenantID, err)
	}
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT set_config('keel.tenant_id', $1, true)`, tenantID); err != nil {
			return fmt.Errorf("scope tenant: %w", err)
		}
		return fn(tx)
	})
}

// CreateTenant registers a new Tenant and returns its id. Authorisation to
// create Tenants is the caller's job (only Platform Admins may).
func (s *Store) CreateTenant(ctx context.Context, slug, name string, isHome bool) (string, error) {
	var id string
	err := s.pool.QueryRow(ctx, `SELECT create_tenant($1, $2, $3)::text`, slug, name, isHome).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("create tenant %q: %w", slug, err)
	}
	return id, nil
}

// CreateTenantThen registers a Tenant and, in the same transaction scoped to
// the new Tenant, runs then (e.g. to record the Activity describing it).
func (s *Store) CreateTenantThen(ctx context.Context, slug, name string, isHome bool, then func(tx pgx.Tx, id string) error) (string, error) {
	var id string
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT create_tenant($1, $2, $3)::text`, slug, name, isHome).Scan(&id); err != nil {
			return fmt.Errorf("create tenant %q: %w", slug, err)
		}
		if _, err := tx.Exec(ctx, `SELECT set_config('keel.tenant_id', $1, true)`, id); err != nil {
			return err
		}
		return then(tx, id)
	})
	return id, err
}
