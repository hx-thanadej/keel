package store_test

import (
	"context"
	"io/fs"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/store"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

// Replicas of keel-api start together and each runs store.Migrate. Several
// rounds, because the unserialised race only loses some of the time.
func TestConcurrentMigratorsApplyOnce(t *testing.T) {
	const rounds, replicas = 5, 4
	files, err := fs.Glob(store.Migrations, "*.sql")
	if err != nil || len(files) == 0 {
		t.Fatalf("no embedded migrations: %v", err)
	}
	for round := range rounds {
		ownerURL := storetest.EmptyDB(t)
		errs := make([]error, replicas)
		var wg sync.WaitGroup
		for i := range replicas {
			wg.Go(func() { errs[i] = store.Migrate(context.Background(), ownerURL) })
		}
		wg.Wait()
		for i, err := range errs {
			if err != nil {
				t.Errorf("round %d replica %d: %v", round, i, err)
			}
		}
		c, err := pgx.Connect(context.Background(), ownerURL)
		if err != nil {
			t.Fatal(err)
		}
		var rows, versions int
		if err := c.QueryRow(context.Background(), `SELECT count(*), count(DISTINCT version_id) FROM goose_db_version WHERE version_id > 0`).Scan(&rows, &versions); err != nil {
			t.Fatal(err)
		}
		_ = c.Close(context.Background())
		if rows != len(files) || versions != len(files) {
			t.Errorf("round %d: goose recorded %d rows for %d versions, want %d of each", round, rows, versions, len(files))
		}
	}
}

func holdMigrationLock(t *testing.T, ownerURL string) {
	t.Helper()
	c, err := pgx.Connect(context.Background(), ownerURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	if _, err := c.Exec(context.Background(), `SELECT pg_advisory_lock($1)`, store.MigrationLockKey); err != nil {
		t.Fatal(err)
	}
}

func TestMigrateGivesUpWhenAnotherReplicaHoldsTheLock(t *testing.T) {
	ownerURL := storetest.EmptyDB(t)
	holdMigrationLock(t, ownerURL)
	t.Cleanup(store.SetMigrationLockWait(300 * time.Millisecond))
	start := time.Now()
	err := store.Migrate(context.Background(), ownerURL)
	if err == nil || !strings.Contains(err.Error(), "migration lock not acquired within 300ms") {
		t.Fatalf("Migrate under a held lock = %v, want the lock timeout error", err)
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("lock wait took %s, want about 300ms", took)
	}
	c, err := pgx.Connect(context.Background(), ownerURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close(context.Background()) }()
	var tables int
	if err := c.QueryRow(context.Background(), `SELECT count(*) FROM pg_tables WHERE schemaname = 'public'`).Scan(&tables); err != nil {
		t.Fatal(err)
	}
	if tables != 0 {
		t.Fatalf("Migrate that never got the lock created %d tables", tables)
	}
}

// The lock is held on a connection that is idle outside a transaction, so a
// NO TRANSACTION migration's CREATE INDEX CONCURRENTLY, which waits for open
// transactions, must still finish while it is held.
func TestConcurrentIndexBuildIsNotBlockedByTheMigrationLock(t *testing.T) {
	ownerURL := storetest.EmptyDB(t)
	holdMigrationLock(t, ownerURL)
	c, err := pgx.Connect(context.Background(), ownerURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close(context.Background()) }()
	for _, q := range []string{
		`SET statement_timeout = '10s'`,
		`CREATE TABLE cic (a int)`,
		`CREATE INDEX CONCURRENTLY cic_a ON cic (a)`,
	} {
		if _, err := c.Exec(context.Background(), q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	var valid bool
	if err := c.QueryRow(context.Background(), `SELECT indisvalid FROM pg_index WHERE indexrelid = 'cic_a'::regclass`).Scan(&valid); err != nil || !valid {
		t.Fatalf("cic_a valid = %v, %v; want a valid index", valid, err)
	}
}

// A replica that starts while another is mid-run waits for the lock. The
// holder's NO TRANSACTION migration then builds an index concurrently, which
// waits for every snapshot older than the build, so the waiter must not hold
// one while it waits.
func TestConcurrentIndexBuildIsNotBlockedByAWaitingMigrator(t *testing.T) {
	const wait = 8 * time.Second
	ownerURL := storetest.EmptyDB(t)
	holder, err := pgx.Connect(context.Background(), ownerURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Close(context.Background()) }()
	if _, err := holder.Exec(context.Background(), `SELECT pg_advisory_lock($1)`, store.MigrationLockKey); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.SetMigrationLockWait(wait))
	waiterErr := make(chan error, 1)
	go func() { waiterErr <- store.Migrate(context.Background(), ownerURL) }()

	c, err := pgx.Connect(context.Background(), ownerURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close(context.Background()) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var waiting bool
		if err := c.QueryRow(context.Background(), `SELECT EXISTS (
			SELECT FROM pg_stat_activity WHERE datname = current_database()
			AND pid NOT IN (pg_backend_pid(), $1) AND query LIKE '%advisory_lock%')`, holder.PgConn().PID()).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("second migrator never asked for the lock")
		}
		time.Sleep(20 * time.Millisecond)
	}

	start := time.Now()
	for _, q := range []string{
		`CREATE TABLE cic (a int)`,
		`CREATE INDEX CONCURRENTLY cic_a ON cic (a)`,
	} {
		if _, err := c.Exec(context.Background(), q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	took := time.Since(start)
	t.Logf("concurrent index build with a migrator waiting took %s", took)
	if took > 2*time.Second {
		t.Errorf("concurrent index build took %s with a migrator waiting, want well under its %s wait", took, wait)
	}

	_ = holder.Close(context.Background())
	if err := <-waiterErr; err != nil {
		t.Fatalf("waiting migrator after the holder released = %v, want success", err)
	}
}
