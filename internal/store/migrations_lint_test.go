package store_test

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// largeTables are the hot, ever-growing tables. A plain CREATE INDEX on one
// blocks its writes for the length of the build, and migrations run at
// keel-api start. See ADR-0021.
var largeTables = map[string]bool{"cost_facts": true, "activities": true, "findings": true, "webhook_deliveries": true}

// conventionFrom is the first migration the convention binds. 00054 and
// earlier predate it and are already applied.
const conventionFrom = 55

var (
	createIndex = regexp.MustCompile(`(?is)\bCREATE\s+(?:UNIQUE\s+)?INDEX\s+(CONCURRENTLY\s+)?(?:IF\s+NOT\s+EXISTS\s+)?(\w+)\s+ON\s+(?:ONLY\s+)?(?:public\.)?(\w+)`)
	sqlComment  = regexp.MustCompile(`--[^\n]*`)
	migrationNo = regexp.MustCompile(`^(\d+)_.*\.sql$`)
)

func upSection(sql string) string {
	up, _, _ := strings.Cut(sql, "-- +goose Down")
	return up
}

// largeTableIndexProblems reports how sql breaks the large-table index
// convention: each index on a largeTables table must be built CONCURRENTLY,
// preceded by DROP INDEX IF EXISTS of the same name (a failed concurrent build
// leaves an INVALID index that a retry would otherwise trip over), in a
// migration marked NO TRANSACTION.
func largeTableIndexProblems(sql string) []string {
	noTx := regexp.MustCompile(`(?m)^--\s*\+goose\s+NO\s+TRANSACTION\s*$`).MatchString(sql)
	up := upSection(sql)
	code := sqlComment.ReplaceAllString(up, "")
	var out []string
	for _, m := range createIndex.FindAllStringSubmatchIndex(code, -1) {
		name, table := code[m[4]:m[5]], code[m[6]:m[7]]
		if !largeTables[table] {
			continue
		}
		if m[2] < 0 {
			out = append(out, fmt.Sprintf("index %s on %s is not CREATE INDEX CONCURRENTLY", name, table))
		}
		if !noTx {
			out = append(out, fmt.Sprintf("index %s on %s needs -- +goose NO TRANSACTION at the top", name, table))
		}
		drop := regexp.MustCompile(`(?is)\bDROP\s+INDEX\s+IF\s+EXISTS\s+(?:public\.)?` + regexp.QuoteMeta(name) + `\b`)
		if !drop.MatchString(code[:m[0]]) {
			out = append(out, fmt.Sprintf("index %s on %s needs DROP INDEX IF EXISTS %s before it", name, table, name))
		}
	}
	return out
}

func dirProblems(t *testing.T, dir string, from int) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.sql"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no migrations in %s: %v", dir, err)
	}
	var out []string
	for _, f := range files {
		m := migrationNo.FindStringSubmatch(filepath.Base(f))
		if m == nil {
			t.Fatalf("migration %s is not named NNNNN_name.sql", f)
		}
		if n, _ := strconv.Atoi(m[1]); n < from {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range largeTableIndexProblems(string(b)) {
			out = append(out, filepath.Base(f)+": "+p)
		}
	}
	return out
}

func TestMigrationsBuildLargeTableIndexesConcurrently(t *testing.T) {
	if p := dirProblems(t, "migrations", conventionFrom); len(p) > 0 {
		t.Fatalf("large-table index convention (ADR-0021) broken:\n%s", strings.Join(p, "\n"))
	}
}

func TestLargeTableIndexCheckFlagsABadMigration(t *testing.T) {
	if p := dirProblems(t, "testdata/badmigrations", 0); len(p) != 3 {
		t.Fatalf("bad fixture problems %v, want 3 (not concurrent, no NO TRANSACTION, no DROP INDEX IF EXISTS)", p)
	}
	good := "-- +goose NO TRANSACTION\n-- +goose Up\nDROP INDEX IF EXISTS cost_facts_x;\nCREATE INDEX CONCURRENTLY cost_facts_x ON cost_facts (a);\n-- +goose Down\nDROP INDEX CONCURRENTLY IF EXISTS cost_facts_x;\n"
	if p := largeTableIndexProblems(good); len(p) != 0 {
		t.Fatalf("convention-following migration flagged: %v", p)
	}
	small := "-- +goose Up\nCREATE INDEX teams_x ON teams (a);\n"
	if p := largeTableIndexProblems(small); len(p) != 0 {
		t.Fatalf("index on a small table flagged: %v", p)
	}
	noTx := strings.Replace(good, "-- +goose NO TRANSACTION\n", "", 1)
	if p := largeTableIndexProblems(noTx); len(p) != 1 {
		t.Fatalf("missing NO TRANSACTION problems %v, want 1", p)
	}
}
