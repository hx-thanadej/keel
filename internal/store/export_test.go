package store

import "time"

// Migrations is the embedded migration set, for tests that walk versions.
var Migrations = mustSub(migrations, "migrations")

// MigrationLockKey is the advisory lock Migrate holds.
const MigrationLockKey = migrationLockKey

// SetMigrationLockWait changes Migrate's lock wait until restore is called.
func SetMigrationLockWait(d time.Duration) (restore func()) {
	old := migrationLockWait
	migrationLockWait = d
	return func() { migrationLockWait = old }
}
