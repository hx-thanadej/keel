package store

// Migrations is the embedded migration set, for tests that walk versions.
var Migrations = mustSub(migrations, "migrations")
