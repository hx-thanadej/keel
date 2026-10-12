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
var largeTables = map[string]bool{
	"cost_facts": true, "activities": true, "findings": true, "webhook_deliveries": true,
	"utilisation_daily": true, "k8s_namespace_costs": true, "release_components": true,
}

// conventionFrom is the first migration the convention binds. 00054 and
// earlier predate it and are already applied.
const conventionFrom = 55

// The patterns below run on normaliseSQL output: lower case, no comments, no
// identifier quotes. ident matches a name with an optional schema prefix;
// tableName strips the prefix.
const ident = `[\w$]+(?:\.[\w$]+)?`

var (
	createIndex  = regexp.MustCompile(`\bcreate\s+(?:unique\s+)?index\s+(concurrently\s+)?(?:if\s+not\s+exists\s+)?(?:(` + ident + `)\s+)??on\s+(?:only\s+)?(` + ident + `)`)
	alterTable   = regexp.MustCompile(`\balter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?(` + ident + `)([^;]*)`)
	uniqueClause = regexp.MustCompile(`\b(unique|primary\s+key|exclude)\b(\s+using\s+index\b)?`)
	reindex      = regexp.MustCompile(`\breindex\s+(?:\([^)]*\)\s*)?table\s+(concurrently\s+)?(` + ident + `)`)
	literal      = regexp.MustCompile(`'(?:[^']|'')*'`)
	doBlock      = regexp.MustCompile(`\bdo\s+(\$[\w]*\$)`)
	noTxMarker   = regexp.MustCompile(`(?m)^--\s*\+goose\s+NO\s+TRANSACTION\s*$`)
	migrationNo  = regexp.MustCompile(`^(\d+)_.*\.sql$`)
)

func upSection(sql string) string {
	up, _, _ := strings.Cut(sql, "-- +goose Down")
	return up
}

// normaliseSQL lower-cases sql, drops -- and /* */ comments, and removes
// double quotes from identifiers, so the lint sees one spelling of each
// statement. String literals and dollar-quoted bodies are kept as code: a DO
// block's statements are linted too.
func normaliseSQL(sql string) string {
	var b strings.Builder
	for i := 0; i < len(sql); i++ {
		switch {
		case strings.HasPrefix(sql[i:], "--"):
			for i < len(sql) && sql[i] != '\n' {
				i++
			}
			b.WriteByte('\n')
		case strings.HasPrefix(sql[i:], "/*"):
			depth := 0
			for ; i < len(sql); i++ {
				if strings.HasPrefix(sql[i:], "/*") {
					depth++
					i++
				} else if strings.HasPrefix(sql[i:], "*/") {
					depth--
					i++
					if depth == 0 {
						break
					}
				}
			}
			b.WriteByte(' ')
		case sql[i] == '\'':
			j := i + 1
			for j < len(sql) && (sql[j] != '\'' || strings.HasPrefix(sql[j:], "''")) {
				if sql[j] == '\'' {
					j++
				}
				j++
			}
			b.WriteString(sql[i:min(j+1, len(sql))])
			i = j
		case sql[i] == '"':
			j := i + 1
			for j < len(sql) && sql[j] != '"' {
				j++
			}
			b.WriteString(sql[i+1 : j])
			i = j
		default:
			b.WriteByte(sql[i])
		}
	}
	return strings.ToLower(b.String())
}

func tableName(name string) string {
	_, t, ok := strings.Cut(name, ".")
	if !ok {
		return name
	}
	return t
}

// doBlockSpans returns the byte ranges of DO blocks' bodies in code.
func doBlockSpans(code string) [][2]int {
	var spans [][2]int
	for _, m := range doBlock.FindAllStringSubmatchIndex(code, -1) {
		tag := code[m[2]:m[3]]
		end := strings.Index(code[m[1]:], tag)
		if end < 0 {
			end = len(code) - m[1]
		}
		spans = append(spans, [2]int{m[1], m[1] + end})
	}
	return spans
}

func inSpan(spans [][2]int, at int) bool {
	for _, s := range spans {
		if at >= s[0] && at < s[1] {
			return true
		}
	}
	return false
}

// largeTableIndexProblems reports how sql breaks the large-table index
// convention: each index on a largeTables table must be named, built
// CONCURRENTLY outside any DO block, preceded by DROP INDEX IF EXISTS of the
// same name (a failed concurrent build leaves an INVALID index that a retry
// would otherwise trip over), in a migration marked NO TRANSACTION. A UNIQUE
// or PRIMARY KEY constraint added by ALTER TABLE builds its index under an
// exclusive lock, so it must attach a concurrently built one (USING INDEX).
func largeTableIndexProblems(sql string) []string {
	noTx := noTxMarker.MatchString(sql)
	code := normaliseSQL(upSection(sql))
	dos := doBlockSpans(code)
	var out []string
	for _, m := range createIndex.FindAllStringSubmatchIndex(code, -1) {
		table := tableName(code[m[6]:m[7]])
		if !largeTables[table] {
			continue
		}
		name := "(unnamed)"
		if m[4] >= 0 {
			name = tableName(code[m[4]:m[5]])
		}
		if m[2] < 0 {
			out = append(out, fmt.Sprintf("index %s on %s is not CREATE INDEX CONCURRENTLY", name, table))
		}
		if inSpan(dos, m[0]) {
			out = append(out, fmt.Sprintf("index %s on %s is inside a DO block, where CREATE INDEX CONCURRENTLY cannot run", name, table))
		}
		if !noTx {
			out = append(out, fmt.Sprintf("index %s on %s needs -- +goose NO TRANSACTION at the top", name, table))
		}
		if m[4] < 0 {
			out = append(out, fmt.Sprintf("index on %s is unnamed; name it so DROP INDEX IF EXISTS can precede it", table))
			continue
		}
		drop := regexp.MustCompile(`\bdrop\s+index\s+(?:concurrently\s+)?if\s+exists\s+(?:[\w$]+\.)?` + regexp.QuoteMeta(name) + `\b`)
		if !drop.MatchString(code[:m[0]]) {
			out = append(out, fmt.Sprintf("index %s on %s needs DROP INDEX IF EXISTS %s before it", name, table, name))
		}
	}
	for _, m := range alterTable.FindAllStringSubmatch(code, -1) {
		table := tableName(m[1])
		if !largeTables[table] {
			continue
		}
		for _, u := range uniqueClause.FindAllStringSubmatch(literal.ReplaceAllString(m[2], "''"), -1) {
			switch {
			case u[1] == "exclude":
				out = append(out, fmt.Sprintf("ALTER TABLE %s ADD EXCLUDE builds its index under a write lock and cannot attach a concurrently built one", table))
			case u[2] == "":
				kind := "ADD UNIQUE"
				if u[1] != "unique" {
					kind = "ADD PRIMARY KEY"
				}
				out = append(out, fmt.Sprintf("ALTER TABLE %s %s builds its index under a write lock; build it CONCURRENTLY and attach it with USING INDEX", table, kind))
			}
		}
	}
	for _, m := range reindex.FindAllStringSubmatch(code, -1) {
		if table := tableName(m[2]); largeTables[table] && m[1] == "" {
			out = append(out, fmt.Sprintf("REINDEX TABLE %s blocks its writes; use REINDEX TABLE CONCURRENTLY", table))
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

func TestLargeTableIndexCheckCases(t *testing.T) {
	const noTx = "-- +goose NO TRANSACTION\n-- +goose Up\n"
	for _, c := range []struct {
		name, sql string
		want      []string // substrings, one per expected problem
	}{
		{"quoted identifiers", `CREATE INDEX "cost_facts_x" ON "cost_facts" (a);`, []string{"not CREATE INDEX CONCURRENTLY", "NO TRANSACTION", "DROP INDEX IF EXISTS"}},
		{"quoted schema and table", noTx + `DROP INDEX IF EXISTS x; CREATE INDEX x ON "public"."cost_facts" (a);`, []string{"not CREATE INDEX CONCURRENTLY"}},
		{"unnamed index", noTx + `CREATE INDEX CONCURRENTLY ON cost_facts (a);`, []string{"unnamed"}},
		{"unnamed plain index", `CREATE INDEX ON cost_facts (a);`, []string{"not CREATE INDEX CONCURRENTLY", "NO TRANSACTION", "unnamed"}},
		{"upper-case names", noTx + `DROP INDEX IF EXISTS X; CREATE INDEX X ON COST_FACTS (a);`, []string{"not CREATE INDEX CONCURRENTLY"}},
		{"block comment between tokens", noTx + `DROP INDEX IF EXISTS x; CREATE INDEX /* hot */ x ON cost_facts (a);`, []string{"not CREATE INDEX CONCURRENTLY"}},
		{"block comment hides old statement", noTx + "/* CREATE INDEX x ON cost_facts (a);\n */ SELECT 1;", nil},
		{"line comment between tokens", noTx + "DROP INDEX IF EXISTS x; CREATE INDEX x -- why\nON cost_facts (a);", []string{"not CREATE INDEX CONCURRENTLY"}},
		{"line comment marker inside a string", noTx + `COMMENT ON TABLE teams IS 'a -- b'; DROP INDEX IF EXISTS x; CREATE INDEX x ON cost_facts (a);`, []string{"not CREATE INDEX CONCURRENTLY"}},
		{"other schema", noTx + `DROP INDEX IF EXISTS keel.x; CREATE INDEX x ON keel.cost_facts (a);`, []string{"not CREATE INDEX CONCURRENTLY"}},
		{"DO block", noTx + "DO $$ BEGIN\n DROP INDEX IF EXISTS x;\n CREATE INDEX CONCURRENTLY x ON cost_facts (a);\nEND $$;", []string{"DO block"}},
		{"tagged DO block", noTx + "DO $body$ BEGIN EXECUTE 'DROP INDEX IF EXISTS x; CREATE INDEX CONCURRENTLY x ON cost_facts (a)'; END $body$;", []string{"DO block"}},
		{"ADD UNIQUE", `ALTER TABLE cost_facts ADD UNIQUE (a, b);`, []string{"ADD UNIQUE"}},
		{"ADD PRIMARY KEY", `ALTER TABLE public.activities ADD PRIMARY KEY (id);`, []string{"ADD PRIMARY KEY"}},
		{"ADD CONSTRAINT UNIQUE", `ALTER TABLE ONLY findings ADD CONSTRAINT findings_u UNIQUE (a), ALTER COLUMN b SET NOT NULL;`, []string{"ADD UNIQUE"}},
		{"ADD COLUMN UNIQUE", `ALTER TABLE findings ADD COLUMN c text UNIQUE;`, []string{"ADD UNIQUE"}},
		{"ADD CONSTRAINT UNIQUE USING INDEX", noTx + `DROP INDEX IF EXISTS findings_u; CREATE UNIQUE INDEX CONCURRENTLY findings_u ON findings (a);
			ALTER TABLE findings ADD CONSTRAINT findings_u UNIQUE USING INDEX findings_u;`, nil},
		{"ADD COLUMN DEFAULT 'unique'", `ALTER TABLE findings ADD COLUMN c text DEFAULT 'unique';`, nil},
		{"ADD COLUMN DEFAULT quoting 'unique'", `ALTER TABLE findings ADD COLUMN c text DEFAULT 'it''s unique';`, nil},
		{"ADD EXCLUDE", `ALTER TABLE cost_facts ADD CONSTRAINT x EXCLUDE USING gist (a WITH =);`, []string{"ADD EXCLUDE"}},
		{"REINDEX TABLE", `REINDEX TABLE public.cost_facts;`, []string{"REINDEX TABLE cost_facts"}},
		{"REINDEX with options", `REINDEX (VERBOSE) TABLE activities;`, []string{"REINDEX TABLE activities"}},
		{"REINDEX TABLE CONCURRENTLY", noTx + `REINDEX TABLE CONCURRENTLY cost_facts;`, nil},
		{"REINDEX on a small table", `REINDEX TABLE teams;`, nil},
		{"ADD PRIMARY KEY on a small table", `ALTER TABLE teams ADD PRIMARY KEY (id);`, nil},
		{"utilisation_daily is large", `CREATE INDEX x ON utilisation_daily (a);`, []string{"not CREATE INDEX CONCURRENTLY", "NO TRANSACTION", "DROP INDEX IF EXISTS"}},
		{"k8s_namespace_costs is large", `CREATE INDEX x ON k8s_namespace_costs (a);`, []string{"not CREATE INDEX CONCURRENTLY", "NO TRANSACTION", "DROP INDEX IF EXISTS"}},
		{"release_components is large", `CREATE INDEX x ON release_components (a);`, []string{"not CREATE INDEX CONCURRENTLY", "NO TRANSACTION", "DROP INDEX IF EXISTS"}},
		{"schema-qualified drop", noTx + `DROP INDEX CONCURRENTLY IF EXISTS public.x; CREATE INDEX CONCURRENTLY x ON cost_facts (a);`, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := largeTableIndexProblems(c.sql)
			if len(got) != len(c.want) {
				t.Fatalf("problems %q, want %d matching %q", got, len(c.want), c.want)
			}
			for i, w := range c.want {
				if !strings.Contains(got[i], w) {
					t.Errorf("problem %d = %q, want it to mention %q", i, got[i], w)
				}
			}
		})
	}
}
