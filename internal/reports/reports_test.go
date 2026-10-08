package reports_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/budget"
	"github.com/hx-thanadej/keel/internal/dora"
	"github.com/hx-thanadej/keel/internal/flow/flowtest"
	"github.com/hx-thanadej/keel/internal/reports"
	"github.com/hx-thanadej/keel/internal/rightsize"
	"github.com/hx-thanadej/keel/internal/store"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestMonthlyReport(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, err := s.CreateTenant(ctx, "tat", "TAT <Thailand>", false)
	must(t, err)
	other, err := s.CreateTenant(ctx, "kbank", "KBank", false)
	must(t, err)
	var project string
	must(t, s.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		var team, env, svc, rel string
		if err := tx.QueryRow(ctx, `INSERT INTO teams (tenant_id, slug, name) VALUES ($1, 'crm', 'CRM') RETURNING id`, tenant).Scan(&team); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO projects (tenant_id, team_id, slug, name) VALUES ($1, $2, 'tat-crm', 'TAT CRM') RETURNING id`, tenant, team).Scan(&project); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO environments (tenant_id, project_id, name) VALUES ($1, $2, 'prod') RETURNING id`, tenant, project).Scan(&env); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO services (tenant_id, project_id, team_id, slug, name) VALUES ($1, $2, $3, 'crm-api', 'API') RETURNING id`, tenant, project, team).Scan(&svc); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO releases (tenant_id, service_id, version, images, created_by, created_at) VALUES ($1, $2, '1.0', '[]', 'p', '2026-09-10') RETURNING id`, tenant, svc).Scan(&rel); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO promotions (tenant_id, release_id, environment_id, state, requested_by, requested_at, deployed_at) VALUES ($1, $2, $3, 'deployed', 'u', '2026-09-10 02:00', '2026-09-10 04:00')`, tenant, rel, env); err != nil {
			return err
		}
		// Open at month end, raised in September.
		if _, err := tx.Exec(ctx, `INSERT INTO findings (tenant_id, kind, fingerprint, severity, title, first_seen_at) VALUES ($1, 'vulnerability', 'a', 'critical', 'x', '2026-09-05')`, tenant); err != nil {
			return err
		}
		// Raised in October: not in September's report.
		if _, err := tx.Exec(ctx, `INSERT INTO findings (tenant_id, kind, fingerprint, severity, title, first_seen_at) VALUES ($1, 'vulnerability', 'b', 'high', 'y', '2026-10-01 10:00')`, tenant); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO exceptions (tenant_id, fingerprint, reason, state, requested_by, decided_by, decided_at, approved_at, expires_at)
			VALUES ($1, 'a', 'vendor fix pending', 'approved', 'u', 'v', '2026-09-20', '2026-09-20', '2026-10-15')`, tenant)
		return err
	}))
	_, err = budget.Service{Store: s}.Create(ctx, tenant, budget.Budget{ProjectID: project, Name: "tat-crm 2026", Year: 2026, Amount: "365000"})
	must(t, err)

	now := time.Date(2026, 10, 1, 1, 0, 0, 0, time.UTC)
	svc := reports.Service{Store: s, Budgets: budget.Service{Store: s}, DORA: dora.Service{Store: s},
		Savings: rightsize.Tracker{Service: rightsize.Service{Store: s}}, Now: func() time.Time { return now }}

	n, err := svc.Run(ctx)
	must(t, err)
	if n != 2 {
		t.Fatalf("Run made %d reports, want one per Tenant", n)
	}
	if n, err := svc.Run(ctx); err != nil || n != 0 {
		t.Fatalf("second Run made %d (%v), want none", n, err)
	}

	sep, _ := reports.ParsePeriod("2026-09")
	r, page, err := svc.Get(ctx, tenant, sep)
	must(t, err)
	if len(r.Budgets) != 1 || r.Budgets[0].MonthBudget != "30000.00" || r.Budgets[0].Project != "TAT CRM" {
		t.Fatalf("budgets = %+v", r.Budgets)
	}
	if r.DORA.Deployments != 1 {
		t.Fatalf("dora deployments = %d", r.DORA.Deployments)
	}
	if r.Findings.OpenBySeverity["critical"] != 1 || r.Findings.OpenBySeverity["high"] != 0 || r.Findings.Raised != 1 {
		t.Fatalf("findings = %+v", r.Findings)
	}
	if r.Exceptions.Active != 1 || r.Exceptions.Granted != 1 || r.Exceptions.Expiring != 1 {
		t.Fatalf("exceptions = %+v", r.Exceptions)
	}
	if !strings.Contains(page, "TAT &lt;Thailand&gt;") || strings.Contains(page, "TAT <Thailand>") {
		t.Fatal("tenant name is not escaped in the HTML")
	}
	if !strings.Contains(page, "30000.00") {
		t.Fatal("HTML lacks the month budget")
	}

	// Each Tenant sees only its own reports.
	if _, _, err := svc.Get(ctx, other, sep); err != nil {
		t.Fatalf("other tenant's own report: %v", err)
	}
	list, err := svc.List(ctx, other)
	must(t, err)
	if len(list) != 1 || list[0].Period != "2026-09" {
		t.Fatalf("list = %+v", list)
	}
	oct, _ := reports.ParsePeriod("2026-10")
	if _, err := svc.Generate(ctx, tenant, oct, reports.SystemActor()); !errors.Is(err, reports.ErrPeriod) {
		t.Fatalf("unfinished month: %v", err)
	}
	if _, _, err := svc.Get(ctx, tenant, oct); !errors.Is(err, reports.ErrNotFound) {
		t.Fatalf("missing report: %v", err)
	}
}

func service(s *store.Store, now *time.Time) reports.Service {
	return reports.Service{Store: s, Budgets: budget.Service{Store: s}, DORA: dora.Service{Store: s},
		Savings: rightsize.Tracker{Service: rightsize.Service{Store: s}}, Now: func() time.Time { return *now }}
}

func TestExceptionsInForceFollowApprovalAndRevocation(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, err := s.CreateTenant(ctx, "tat", "TAT", false)
	must(t, err)
	must(t, s.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO exceptions (tenant_id, fingerprint, reason, state, requested_by, decided_by, created_at, decided_at, approved_at, revoked_at, expires_at) VALUES
			($1, 'a', 'approved in August, revoked mid September', 'revoked', 'u', 'v', '2026-08-09', '2026-08-10', '2026-08-10', '2026-09-15', '2026-11-01'),
			($1, 'b', 'approved in July, revoked in August', 'revoked', 'u', 'v', '2026-07-09', '2026-07-10', '2026-07-10', '2026-08-20', '2026-12-01'),
			($1, 'c', 'approved in September, still standing', 'approved', 'u', 'v', '2026-09-04', '2026-09-05', '2026-09-05', NULL, '2026-10-20')`, tenant)
		return err
	}))
	now := time.Date(2026, 10, 1, 1, 0, 0, 0, time.UTC)
	sep, _ := reports.ParsePeriod("2026-09")
	r, err := service(s, &now).Generate(ctx, tenant, sep, reports.SystemActor())
	must(t, err)
	if want := (reports.Exceptions{Active: 2, Granted: 1, Expiring: 1}); r.Exceptions != want {
		t.Fatalf("exceptions = %+v, want %+v", r.Exceptions, want)
	}
}

func generated(t *testing.T, s *store.Store, tenant string) int {
	t.Helper()
	var n int
	must(t, s.InTenant(context.Background(), tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT count(*) FROM activities WHERE type = 'keel.report.generated'`).Scan(&n)
	}))
	return n
}

func TestRunRefreshesProvisionalReportsOnly(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	provisional, err := s.CreateTenant(ctx, "tat", "TAT", false)
	must(t, err)
	final, err := s.CreateTenant(ctx, "kbank", "KBank", false)
	must(t, err)
	must(t, s.InTenant(ctx, provisional, func(tx pgx.Tx) error {
		var team, project string
		if err := tx.QueryRow(ctx, `INSERT INTO teams (tenant_id, slug, name) VALUES ($1, 'crm', 'CRM') RETURNING id`, provisional).Scan(&team); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `INSERT INTO projects (tenant_id, team_id, slug, name) VALUES ($1, $2, 'tat-crm', 'TAT CRM') RETURNING id`, provisional, team).Scan(&project)
	}))
	var project string
	must(t, s.InTenant(ctx, provisional, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT id FROM projects`).Scan(&project)
	}))
	// No cost data has landed for the Budget, so its month is not final.
	_, err = budget.Service{Store: s}.Create(ctx, provisional, budget.Budget{ProjectID: project, Name: "tat-crm 2026", Year: 2026, Amount: "365000"})
	must(t, err)

	now := time.Date(2026, 10, 1, 1, 0, 0, 0, time.UTC)
	svc := service(s, &now)
	n, err := svc.Run(ctx)
	must(t, err)
	if n != 2 {
		t.Fatalf("first Run made %d reports, want 2", n)
	}
	sep, _ := reports.ParsePeriod("2026-09")
	for tenant, want := range map[string]bool{provisional: false, final: true} {
		r, _, err := svc.Get(ctx, tenant, sep)
		must(t, err)
		if r.Final != want {
			t.Fatalf("tenant %s final = %v, want %v", tenant, r.Final, want)
		}
	}
	for tenant, want := range map[string]bool{provisional: false, final: true} {
		list, err := svc.List(ctx, tenant)
		must(t, err)
		if len(list) != 1 || list[0].Final != want {
			t.Fatalf("tenant %s list = %+v, want one report with final=%v", tenant, list, want)
		}
	}
	for _, tenant := range []string{provisional, final} {
		must(t, s.InTenant(ctx, tenant, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO findings (tenant_id, kind, fingerprint, severity, title, first_seen_at) VALUES ($1, 'vulnerability', 'late', 'high', 'late', '2026-09-29')`, tenant)
			return err
		}))
	}

	now = now.Add(time.Hour)
	if n, err := svc.Run(ctx); err != nil || n != 1 {
		t.Fatalf("second Run refreshed %d (%v), want the provisional one", n, err)
	}
	if r, _, err := svc.Get(ctx, provisional, sep); err != nil || r.Findings.Raised != 1 {
		t.Fatalf("provisional report not refreshed: raised %d (%v)", r.Findings.Raised, err)
	}
	if r, _, err := svc.Get(ctx, final, sep); err != nil || r.Findings.Raised != 0 {
		t.Fatalf("final report changed: raised %d (%v)", r.Findings.Raised, err)
	}

	now = now.Add(time.Hour)
	if n, err := svc.Run(ctx); err != nil || n != 0 {
		t.Fatalf("third Run with nothing new made %d (%v), want 0", n, err)
	}
	if p, f := generated(t, s, provisional), generated(t, s, final); p != 2 || f != 1 {
		t.Fatalf("generation activities: provisional %d, final %d; want 2 and 1", p, f)
	}
}

func TestConcurrentRunsRecordOneActivity(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	var tenants []string
	for _, slug := range []string{"tat", "kbank", "scb", "ktb"} {
		id, err := s.CreateTenant(ctx, slug, slug, false)
		must(t, err)
		tenants = append(tenants, id)
	}
	now := time.Date(2026, 10, 1, 1, 0, 0, 0, time.UTC)
	svc := service(s, &now)
	var wg sync.WaitGroup
	errs := make([]error, 4)
	for i := range errs {
		wg.Go(func() { _, errs[i] = svc.Run(ctx) })
	}
	wg.Wait()
	must(t, errors.Join(errs...))
	for _, tenant := range tenants {
		if n := generated(t, s, tenant); n != 1 {
			t.Fatalf("tenant %s has %d generation activities, want 1", tenant, n)
		}
	}
}

func TestRiverJobGeneratesReports(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, err := s.CreateTenant(ctx, "tat", "TAT", false)
	must(t, err)
	now := time.Date(2026, 10, 1, 1, 0, 0, 0, time.UTC)
	svc := service(s, &now)
	c, _ := flowtest.Client(t, s, svc.Register)
	svc.SetClient(c)
	sep, _ := reports.ParsePeriod("2026-09")
	deadline := time.Now().Add(15 * time.Second)
	for {
		_, _, err := svc.Get(ctx, tenant, sep)
		if err == nil {
			break
		}
		if !errors.Is(err, reports.ErrNotFound) || time.Now().After(deadline) {
			t.Fatalf("periodic job never generated the report: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
