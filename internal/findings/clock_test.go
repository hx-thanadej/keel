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

// Finding and recommendation timestamps are compared with service clocks
// (reports, evidence, savings, the SLA run), so every writer binds them from
// its clock (#176). This scans the SQL in Keel's Go source for the database
// clock creeping back in.
func TestFindingTimestampsComeFromTheServiceClock(t *testing.T) {
	dbClock := regexp.MustCompile(`\b(resolved_at|overdue_at|first_seen_at|applied_at)\s*=\s*(coalesce\([^()]*,\s*)?now\(\)`)
	oneArgExcepted := regexp.MustCompile(`finding_excepted\(\s*\w+\s*\)`)
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
				sql, at := lit.Value, fset.Position(lit.Pos())
				if strings.Contains(sql, "INSERT INTO findings") {
					checked++
					if !strings.Contains(sql, "first_seen_at") {
						t.Errorf("%s: INSERT INTO findings without first_seen_at from the service clock", at)
					}
				}
				if m := dbClock.FindString(sql); m != "" {
					t.Errorf("%s: %q takes the database clock; bind the service clock instead", at, m)
				}
				if m := oneArgExcepted.FindString(sql); m != "" {
					t.Errorf("%s: %q needs the service clock's time as its second argument", at, m)
				}
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
