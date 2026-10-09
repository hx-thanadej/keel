package findings_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const dbClock = `(now\(\)|current_timestamp|localtimestamp|(statement|transaction|clock)_timestamp\(\))`

var (
	writesFindings = regexp.MustCompile(`(?i)\b(insert\s+into|update)\s+findings\b`)
	insertFindings = regexp.MustCompile(`(?i)\binsert\s+into\s+findings\b`)
	anyDBClock     = regexp.MustCompile(`(?i)\b` + dbClock)
	lastSeen       = regexp.MustCompile(`(?i)\blast_seen_at\s*=\s*` + dbClock)
	firstSeenSet   = regexp.MustCompile(`(?i)\bfirst_seen_at\s*=`)
	clockedColumn  = `(due_at|overdue_at|first_seen_at|resolved_at|applied_at)`
	comparedWithDB = regexp.MustCompile(`(?i)\b` + clockedColumn + `\s*(=|<|>|<=|>=)\s*(coalesce\([^()]*,\s*)?` + dbClock + `|\b` + dbClock + `\s*(<|>|<=|>=)\s*` + clockedColumn + `\b`)
	exceptedNoTime = regexp.MustCompile(`(?i)\bfinding_excepted\(\s*[\w.*]+\s*\)`)
	exceptedAtDB   = regexp.MustCompile(`(?i)\bfinding_excepted\([^;]*?,\s*` + dbClock)
)

// Finding and recommendation timestamps are compared with service clocks
// (reports, evidence, savings, the SLA run, the promotion gate), so every
// writer binds them from its clock and every reader compares them with it
// (#176). This scans the SQL literals in Keel's Go source for the database
// clock creeping back in; last_seen_at is the one column left on it.
func TestFindingTimestampsComeFromTheServiceClock(t *testing.T) {
	var checked int
	for _, root := range []string{"../../internal", "../../cmd"} {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				return err
			}
			ast.Inspect(f, func(n ast.Node) bool {
				lit, ok := n.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				checked += len(checkSQL(lit.Value, func(msg string) { t.Errorf("%s: %s", fset.Position(lit.Pos()), msg) }))
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if checked == 0 {
		t.Fatal("found no Finding inserts to check")
	}
}

// checkSQL reports each way sql takes the database clock for a compared
// timestamp and returns the Finding inserts it checked.
func checkSQL(sql string, report func(string)) []string {
	inserts := insertFindings.FindAllString(sql, -1)
	if len(inserts) > 0 && !strings.Contains(strings.ToLower(sql), "first_seen_at") {
		report("INSERT INTO findings without first_seen_at from the service clock")
	}
	if writesFindings.MatchString(sql) {
		if m := anyDBClock.FindString(lastSeen.ReplaceAllString(sql, "")); m != "" {
			report("a Finding write takes " + m + "; bind the service clock instead")
		}
		if m := firstSeenSet.FindString(sql); m != "" {
			report("a Finding write sets first_seen_at after insert (" + m + ")")
		}
	}
	for _, re := range []*regexp.Regexp{comparedWithDB, exceptedAtDB} {
		if m := re.FindString(sql); m != "" {
			report(m + " takes the database clock; bind the service clock instead")
		}
	}
	if m := exceptedNoTime.FindString(sql); m != "" {
		report(m + " needs the service clock's time as its second argument")
	}
	return inserts
}

func TestCheckSQLCatchesTheDatabaseClock(t *testing.T) {
	for _, sql := range []string{
		`INSERT INTO findings (tenant_id, kind) VALUES ($1, $2)`,
		`INSERT INTO findings (tenant_id, first_seen_at) VALUES ($1, now())`,
		`insert into findings (tenant_id, kind) values ($1, $2)`,
		`UPDATE findings SET resolved_at = NOW() WHERE id = $1`,
		`UPDATE findings SET resolved_at = current_timestamp WHERE id = $1`,
		`UPDATE findings SET status = 'resolved', resolved_at = statement_timestamp() WHERE id = $1`,
		`INSERT INTO findings (tenant_id, first_seen_at) VALUES ($1, $2) ON CONFLICT (tenant_id, fingerprint) WHERE status = 'open' DO UPDATE SET first_seen_at = excluded.first_seen_at`,
		`SELECT count(*) FROM findings f WHERE NOT finding_excepted(f.*)`,
		`SELECT count(*) FROM findings f WHERE NOT finding_excepted(f, now())`,
		`SELECT 1 FROM findings WHERE status = 'open' AND due_at < now()`,
		`SELECT 1 FROM findings WHERE now() > due_at`,
		`UPDATE recommendations SET applied_at = coalesce(applied_at, now()) WHERE id = $1`,
	} {
		var reports []string
		checkSQL(sql, func(msg string) { reports = append(reports, msg) })
		if len(reports) == 0 {
			t.Errorf("missed: %s", sql)
		}
	}
	for _, sql := range []string{
		`INSERT INTO findings (tenant_id, first_seen_at) VALUES ($1, $2) ON CONFLICT (tenant_id, fingerprint) WHERE status = 'open' DO UPDATE SET last_seen_at = now(), detail = excluded.detail`,
		`UPDATE findings SET status = 'resolved', resolved_at = $2 WHERE id = $1`,
		`SELECT 1 FROM findings f WHERE NOT finding_excepted(f, $2) AND due_at < $2`,
		`UPDATE cloud_accounts SET baseline_version = $2, baseline_applied_at = now() WHERE id = $1`,
	} {
		checkSQL(sql, func(msg string) { t.Errorf("false positive %q on: %s", msg, sql) })
	}
}
