package pdpa_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/controls"
	"github.com/hx-thanadej/keel/internal/evidence"
	"github.com/hx-thanadej/keel/internal/integrity"
	"github.com/hx-thanadej/keel/internal/pdpa"
	"github.com/hx-thanadej/keel/internal/store"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

var admin = activity.Actor{Type: activity.ActorHuman, UID: "user:admin@harmonyx.co"}

// clock is the service clock plus a test-controlled offset.
type clock struct {
	base   func() time.Time
	offset time.Duration
}

func newClock() *clock                   { return &clock{base: storetest.Clock()} }
func (c *clock) now() time.Time          { return c.base().Add(c.offset) }
func (c *clock) advance(d time.Duration) { c.offset += d }

func exec(t *testing.T, s *store.Store, tenant, sql string, args ...any) {
	t.Helper()
	if err := s.InTenant(context.Background(), tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), sql, args...)
		return err
	}); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

func scalar[T any](t *testing.T, s *store.Store, tenant, sql string, args ...any) T {
	t.Helper()
	var v T
	if err := s.InTenant(context.Background(), tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), sql, args...).Scan(&v)
	}); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	return v
}

func activities(t *testing.T, s *store.Store, tenant, typ string) int {
	t.Helper()
	return scalar[int](t, s, tenant, `SELECT count(*) FROM activities WHERE type = $1`, typ)
}

// account registers a Cloud Account and a load its billed usage hangs off.
func account(t *testing.T, s *store.Store, tenant, slug string) (accountID, load string) {
	t.Helper()
	ctx := context.Background()
	if err := s.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		var team, project, env string
		if err := tx.QueryRow(ctx, `INSERT INTO teams (tenant_id, slug, name) VALUES ($1, $2, $2) RETURNING id`, tenant, slug).Scan(&team); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO projects (tenant_id, team_id, slug, name) VALUES ($1, $2, $3, $3) RETURNING id`, tenant, team, slug).Scan(&project); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO environments (tenant_id, project_id, name) VALUES ($1, $2, 'prod') RETURNING id`, tenant, project).Scan(&env); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO services (tenant_id, project_id, team_id, slug, name) VALUES ($1, $2, $3, 'api', 'API')`, tenant, project, team); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO cloud_accounts (tenant_id, environment_id, provider, external_id, name) VALUES ($1, $2, 'tencent', $3, $4) RETURNING id`,
			tenant, env, "uin-"+slug, slug+"-prod").Scan(&accountID); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `INSERT INTO cost_loads (tenant_id, provider, billing_account_id, billing_period, line_count, total_billed, unallocated_billed, currency, touched_tenants)
			VALUES ($1, 'tencent', 'payer', '2030-01-01', 1, 1, 0, 'USD', ARRAY[$1::uuid]) RETURNING id`, tenant).Scan(&load)
	}); err != nil {
		t.Fatal(err)
	}
	return accountID, load
}

func fact(t *testing.T, s *store.Store, tenant, load, accountID, sub, region string, start time.Time) int64 {
	t.Helper()
	return scalar[int64](t, s, tenant, `INSERT INTO cost_facts (load_id, tenant_id, current, provider, billing_account_id, sub_account_id, cloud_account_id, allocation_method, billing_period,
		charge_period_start, charge_period_end, charge_category, billed_cost, billing_currency, region_id)
		VALUES ($1, $2, true, 'tencent', 'payer', $3, $4, 'account', date_trunc('month', $5::timestamptz AT TIME ZONE 'UTC')::date, $5, $5, 'Usage', 1, 'USD', $6) RETURNING id`,
		load, tenant, sub, accountID, start, region)
}

type finding struct{ Fingerprint, Status, Severity string }

func findings(t *testing.T, s *store.Store, tenant, kind string) []finding {
	t.Helper()
	var out []finding
	if err := s.InTenant(context.Background(), tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(context.Background(), `SELECT fingerprint, status, severity FROM findings WHERE kind = $1 ORDER BY first_seen_at, fingerprint`, kind)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, pgx.RowToStructByPos[finding])
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func open(list []finding) []string {
	var out []string
	for _, f := range list {
		if f.Status == "open" {
			out = append(out, f.Fingerprint)
		}
	}
	return out
}

func TestResidencyRaisesOneFindingPerLocationOutsideTheRegionSet(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	c := newClock()
	tat, _ := s.CreateTenant(ctx, "tat", "TAT", false)
	acme, _ := s.CreateTenant(ctx, "acme", "Acme", false)
	svc := pdpa.Service{Store: s, Now: c.now, Stores: []pdpa.Location{
		{Kind: "archive", Name: "keel-activity-archive", Region: "ap-southeast-1"},
		{Kind: "bill_bucket", Name: "keel-bills", Region: "ap-bangkok"},
	}}

	acct, load := account(t, s, tat, "crm")
	now := c.now()
	fact(t, s, tat, load, acct, "uin-crm", "ap-bangkok", now.AddDate(0, 0, -3))
	fact(t, s, tat, load, acct, "uin-crm", "ap-singapore", now.AddDate(0, 0, -3))
	fact(t, s, tat, load, acct, "uin-crm", "ap-singapore", now.AddDate(0, 0, -4))
	fact(t, s, tat, load, acct, "uin-crm", "eu-frankfurt", now.AddDate(0, 0, -60)) // billed before the window
	fact(t, s, tat, load, acct, "uin-crm", "", now.AddDate(0, 0, -3))              // global services carry no region

	runs, err := svc.RunResidency(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 2 {
		t.Fatalf("runs %+v", runs)
	}
	archive := "pdpa_residency:archive:keel-activity-archive:ap-southeast-1"
	singapore := "pdpa_residency:cloud_account:tencent:crm-prod:ap-singapore"
	if got := open(findings(t, s, tat, "pdpa_residency")); !slices.Equal(got, []string{archive, singapore}) && !slices.Equal(got, []string{singapore, archive}) {
		t.Fatalf("tat residency Findings %v, want exactly the archive and the Singapore account", got)
	}
	if got := open(findings(t, s, acme, "pdpa_residency")); !slices.Equal(got, []string{archive}) {
		t.Fatalf("acme residency Findings %v, want only the shared archive", got)
	}

	c.advance(time.Hour)
	if _, err := svc.RunResidency(ctx); err != nil {
		t.Fatal(err)
	}
	if got := findings(t, s, tat, "pdpa_residency"); len(got) != 2 {
		t.Fatalf("second run raised again: %+v", got)
	}

	// A platform admin agrees Singapore for TAT: that Finding resolves, the
	// archive's stays open.
	if _, err := svc.Configure(ctx, tat, pdpa.Settings{DataRegions: []string{"ap-bangkok", "ap-singapore"}}, admin); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RunResidency(ctx); err != nil {
		t.Fatal(err)
	}
	got := findings(t, s, tat, "pdpa_residency")
	if o := open(got); len(got) != 2 || !slices.Equal(o, []string{archive}) {
		t.Fatalf("after agreeing ap-singapore: %+v", got)
	}
	if n := activities(t, s, tat, "keel.pdpa.residency.checked"); n != 3 {
		t.Fatalf("%d residency Activities, want one per run", n)
	}
	storetest.ClockedFindings(t, s, "pdpa_residency")
}

// expirable seeds, for every deletable class, one row past its retention
// period and one inside it, plus rows retention must never touch. It returns
// the keys of the expired rows per class. The nth seeding of a Tenant shifts
// its monthly reports back n months so periods stay unique.
func expirable(t *testing.T, s *store.Store, tenant, slug string, n int, now time.Time) map[string]string {
	t.Helper()
	acct, load := account(t, s, tenant, slug)
	day := 24 * time.Hour
	expired := map[string]string{}
	f := func(resolvedAgo time.Duration, fp string) string {
		return scalar[string](t, s, tenant, `INSERT INTO findings (tenant_id, kind, fingerprint, severity, title, status, first_seen_at, last_seen_at, resolved_at)
			VALUES ($1, 'test', $2, 'low', 't', 'resolved', $3, $3, $3) RETURNING id::text`, tenant, fp, now.Add(-resolvedAgo))
	}
	expired["findings"] = f(3*365*day+day, slug+"-old")
	f(3*365*day-day, slug+"-recent")
	referenced := f(4*365*day, slug+"-recommended")
	exec(t, s, tenant, `INSERT INTO recommendations (tenant_id, fingerprint, source, provider, resource_id, resource_type, action, monthly_savings, currency, confidence, finding_id)
		VALUES ($1, $2, 'test', 'tencent', 'r', 'vm', 'resize', 1, 'USD', 0.5, $3)`, tenant, slug+"-rec", referenced)
	exec(t, s, tenant, `INSERT INTO findings (tenant_id, kind, fingerprint, severity, title, first_seen_at, last_seen_at) VALUES ($1, 'test', $2, 'low', 'still open', $3, $3)`,
		tenant, slug+"-open", now.AddDate(-10, 0, 0))

	expired["cost_facts"] = fmt.Sprint(fact(t, s, tenant, load, acct, "uin-"+slug, "ap-bangkok", now.AddDate(-6, 0, 0)))
	fact(t, s, tenant, load, acct, "uin-"+slug, "ap-bangkok", now.AddDate(-4, 0, 0))

	expired["tenant_reports"] = now.AddDate(-6, -n, 0).Format("2006-01") + "-01"
	exec(t, s, tenant, `INSERT INTO tenant_reports (tenant_id, period, generated_at, data, html) VALUES ($1, $2, $3, '{}', '<p>'), ($1, $4, $3, '{}', '<p>')`,
		tenant, expired["tenant_reports"], now, now.AddDate(0, -1-n, 0).Format("2006-01")+"-01")

	expired["utilisation"] = now.Add(-401 * day).Format("2006-01-02")
	for _, d := range []string{expired["utilisation"], now.Add(-399 * day).Format("2006-01-02")} {
		exec(t, s, tenant, `INSERT INTO utilisation_daily (tenant_id, provider, resource_id, resource_type, metric, day, p50, p95, p99, max, samples)
			VALUES ($1, 'k8s', $3, 'k8s_container', 'cpu_cores', $2, 1, 1, 1, 1, 1)`, tenant, d, "c/ns/"+slug+"/x")
	}

	expired["webhook_deliveries"] = slug + "-old"
	exec(t, s, tenant, `INSERT INTO webhook_deliveries (tenant_id, source, delivery_id, event, received_at) VALUES ($1, 'github', $2, 'push', $3), ($1, 'github', $4, 'push', $5)`,
		tenant, slug+"-old", now.Add(-91*day), slug+"-recent", now.Add(-89*day))

	expired["sessions"] = slug + "-old"
	exec(t, s, tenant, `INSERT INTO sessions (id_hash, tenant_id, principal, created_at, expires_at) VALUES (sha256($2::bytea), $1, '{}', $3, $3), (sha256($4::bytea), $1, '{}', $5, $5)`,
		tenant, slug+"-old", now.Add(-31*day), slug+"-recent", now.Add(-29*day))
	return expired
}

// rows counts each deletable class's rows and whether its expired row is
// still there.
func rows(t *testing.T, s *store.Store, tenant string, expired map[string]string) map[string][2]int {
	t.Helper()
	q := map[string][2]string{
		"findings":           {`SELECT count(*) FROM findings`, `SELECT count(*) FROM findings WHERE id::text = $1`},
		"cost_facts":         {`SELECT count(*) FROM cost_facts`, `SELECT count(*) FROM cost_facts WHERE id::text = $1`},
		"tenant_reports":     {`SELECT count(*) FROM tenant_reports`, `SELECT count(*) FROM tenant_reports WHERE period::text = $1`},
		"utilisation":        {`SELECT count(*) FROM utilisation_daily`, `SELECT count(*) FROM utilisation_daily WHERE day::text = $1`},
		"webhook_deliveries": {`SELECT count(*) FROM webhook_deliveries`, `SELECT count(*) FROM webhook_deliveries WHERE delivery_id = $1`},
		"sessions":           {`SELECT count(*) FROM sessions`, `SELECT count(*) FROM sessions WHERE id_hash = sha256($1::bytea)`},
	}
	out := map[string][2]int{}
	for class, sql := range q {
		out[class] = [2]int{scalar[int](t, s, tenant, sql[0]), scalar[int](t, s, tenant, sql[1], expired[class])}
	}
	return out
}

func byTenant(runs []pdpa.RetentionRun, tenant string) pdpa.RetentionRun {
	for _, r := range runs {
		if r.Tenant == tenant {
			return r
		}
	}
	return pdpa.RetentionRun{}
}

func eachClassCounts(t *testing.T, r pdpa.RetentionRun, want int64) {
	t.Helper()
	if len(r.Classes) != 6 {
		t.Fatalf("classes %+v, want the six deletable ones", r.Classes)
	}
	for _, c := range r.Classes {
		if c.Rows != want {
			t.Errorf("%s %s: %d rows, want %d", r.Mode, c.Class, c.Rows, want)
		}
	}
}

func TestRetentionDryRunThenDeletesExactlyTheExpiredRowsAndKeepsTheLogVerifiable(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	c := newClock()
	tat, _ := s.CreateTenant(ctx, "tat", "TAT", false)
	acme, _ := s.CreateTenant(ctx, "acme", "Acme", false)
	svc := pdpa.Service{Store: s, Now: c.now}
	expTAT := expirable(t, s, tat, "tat", 0, c.now())
	expAcme := expirable(t, s, acme, "acme", 0, c.now())

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer := integrity.NewEd25519(priv)
	sealer := integrity.Sealer{Store: s, Signer: signer, Grace: time.Nanosecond, Now: c.now}
	verify := func(when string) {
		t.Helper()
		c.advance(time.Second)
		if _, err := sealer.Seal(ctx, tat); err != nil {
			t.Fatal(err)
		}
		r, err := integrity.Verify(ctx, s, tat, map[string]ed25519.PublicKey{signer.KeyID(): pub})
		if err != nil {
			t.Fatal(err)
		}
		if !r.OK() || r.Covered == 0 {
			t.Fatalf("verify-log %s: %+v", when, r)
		}
	}
	if _, err := svc.Configure(ctx, tat, pdpa.Settings{}, admin); err != nil {
		t.Fatal(err)
	}
	verify("before retention")
	before := rows(t, s, tat, expTAT)
	activitiesBefore := scalar[int](t, s, tat, `SELECT count(*) FROM activities`)

	// Deletion is off by default: a dry run counts exactly the expired rows.
	runs, err := svc.RunRetention(ctx)
	if err != nil {
		t.Fatal(err)
	}
	dry := byTenant(runs, tat)
	if dry.Mode != pdpa.DryRun {
		t.Fatalf("default mode %s", dry.Mode)
	}
	eachClassCounts(t, dry, 1)
	if got := rows(t, s, tat, expTAT); fmt.Sprint(got) != fmt.Sprint(before) {
		t.Fatalf("dry run deleted rows: before %v after %v", before, got)
	}
	if n := activities(t, s, tat, "keel.pdpa.retention.dry_run"); n != 1 {
		t.Fatalf("%d dry-run Activities", n)
	}

	// Enabling deletion is itself an Activity; the next run deletes exactly
	// the expired rows, in TAT only.
	if _, err := svc.Configure(ctx, tat, pdpa.Settings{DeletionEnabled: true}, admin); err != nil {
		t.Fatal(err)
	}
	if n := activities(t, s, tat, "keel.pdpa.deletion.enabled"); n != 1 {
		t.Fatalf("%d deletion.enabled Activities", n)
	}
	acmeBefore := rows(t, s, acme, expAcme)
	runs, err = svc.RunRetention(ctx)
	if err != nil {
		t.Fatal(err)
	}
	del := byTenant(runs, tat)
	if del.Mode != pdpa.Deleted || byTenant(runs, acme).Mode != pdpa.DryRun {
		t.Fatalf("modes tat %s acme %s", del.Mode, byTenant(runs, acme).Mode)
	}
	eachClassCounts(t, del, 1)
	after := rows(t, s, tat, expTAT)
	for class, b := range before {
		if a := after[class]; a[0] != b[0]-1 || b[1] != 1 || a[1] != 0 {
			t.Errorf("%s: rows %d → %d, expired row %d → %d; want exactly the expired row deleted", class, b[0], a[0], b[1], a[1])
		}
	}
	if got := rows(t, s, acme, expAcme); fmt.Sprint(got) != fmt.Sprint(acmeBefore) {
		t.Fatalf("TAT's deletion touched Acme: %v → %v", acmeBefore, got)
	}
	if n := activities(t, s, tat, "keel.pdpa.retention.deleted"); n != 1 {
		t.Fatalf("%d deletion Activities", n)
	}
	if n := scalar[int](t, s, tat, `SELECT count(*) FROM activities`); n != activitiesBefore+3 {
		t.Fatalf("activities %d → %d; retention must only add its own (dry run, enable, delete)", activitiesBefore, n)
	}
	verify("after retention")

	// A legal hold, then an open breach, each hold everything.
	exp2 := expirable(t, s, tat, "tat2", 1, c.now())
	if _, err := svc.Configure(ctx, tat, pdpa.Settings{DeletionEnabled: true, LegalHold: "litigation 2031-17"}, admin); err != nil {
		t.Fatal(err)
	}
	held := rows(t, s, tat, exp2)
	r, err := svc.Retain(ctx, tat)
	if err != nil {
		t.Fatal(err)
	}
	if r.Mode != pdpa.Held || fmt.Sprint(rows(t, s, tat, exp2)) != fmt.Sprint(held) {
		t.Fatalf("legal hold: mode %s, rows %v → %v", r.Mode, held, rows(t, s, tat, exp2))
	}
	if _, err := svc.Configure(ctx, tat, pdpa.Settings{DeletionEnabled: true}, admin); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Declare(ctx, tat, pdpa.Declaration{Title: "laptop lost"}, admin); err != nil {
		t.Fatal(err)
	}
	if r, err = svc.Retain(ctx, tat); err != nil || r.Mode != pdpa.Held || fmt.Sprint(rows(t, s, tat, exp2)) != fmt.Sprint(held) {
		t.Fatalf("open breach: mode %s err %v", r.Mode, err)
	}
	verify("after held runs")
}

func TestBreachClockRaisesOneFindingPerTransition(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	c := newClock()
	tat, _ := s.CreateTenant(ctx, "tat", "TAT", false)
	acme, _ := s.CreateTenant(ctx, "acme", "Acme", false)
	svc := pdpa.Service{Store: s, Now: c.now}
	lead := activity.Actor{Type: activity.ActorHuman, UID: "user:security@harmonyx.co"}

	b, err := svc.Declare(ctx, tat, pdpa.Declaration{Title: "CRM export emailed to the wrong customer"}, lead)
	if err != nil {
		t.Fatal(err)
	}
	if b.State != pdpa.Declared || !b.NotifyBy.Equal(b.AwareAt.Add(72*time.Hour)) {
		t.Fatalf("declared %+v", b)
	}
	step := func(by time.Duration, moved int, state pdpa.State, wantOpen []string, total int) {
		t.Helper()
		c.advance(by)
		n, err := svc.RunClock(ctx)
		if err != nil {
			t.Fatal(err)
		}
		got := findings(t, s, tat, "pdpa_breach")
		if n != moved || scalar[string](t, s, tat, `SELECT state FROM pdpa_breaches WHERE id = $1`, b.ID) != string(state) ||
			!slices.Equal(open(got), wantOpen) || len(got) != total {
			t.Fatalf("at +%s: moved %d (want %d), findings %+v; want state %s, open %v, %d in all", c.offset, n, moved, got, state, wantOpen, total)
		}
	}
	warning, deadline := "pdpa_breach:"+b.ID+":warning", "pdpa_breach:"+b.ID+":deadline"
	step(0, 0, pdpa.Declared, nil, 0)
	step(47*time.Hour+59*time.Minute, 0, pdpa.Declared, nil, 0)
	step(time.Minute, 1, pdpa.Warning, []string{warning}, 1)
	step(time.Hour, 0, pdpa.Warning, []string{warning}, 1)
	step(23*time.Hour, 1, pdpa.Deadline, []string{deadline}, 2)
	step(time.Hour, 0, pdpa.Deadline, []string{deadline}, 2)
	if f := findings(t, s, tat, "pdpa_breach"); f[0].Severity != "high" || f[1].Severity != "critical" {
		t.Fatalf("severities %+v", f)
	}

	if _, err := svc.Notify(ctx, tat, b.ID, pdpa.Notification{}, lead); !errors.Is(err, pdpa.ErrInvalid) {
		t.Fatalf("notify without a reference: %v", err)
	}
	n, err := svc.Notify(ctx, tat, b.ID, pdpa.Notification{Reference: "PDPC-2031-0042"}, lead)
	if err != nil || n.State != pdpa.Notified || n.EndedAt == nil {
		t.Fatalf("notify: %+v %v", n, err)
	}
	step(time.Hour, 0, pdpa.Notified, nil, 2)
	if _, err := svc.Notify(ctx, tat, b.ID, pdpa.Notification{Reference: "again"}, lead); !errors.Is(err, pdpa.ErrState) {
		t.Fatalf("second notify: %v", err)
	}
	for typ, want := range map[string]int{"keel.pdpa.breach.declared": 1, "keel.pdpa.breach.warning": 1, "keel.pdpa.breach.deadline": 1, "keel.pdpa.breach.notified": 1} {
		if got := activities(t, s, tat, typ); got != want {
			t.Errorf("%d %s Activities, want %d", got, typ, want)
		}
	}

	// Awareness 60h ago enters warning at declaration with its one Finding;
	// closing without notifying needs a reason and resolves it.
	aware := c.now().Add(-60 * time.Hour)
	late, err := svc.Declare(ctx, acme, pdpa.Declaration{Title: "bucket briefly public", AwareAt: &aware}, lead)
	if err != nil || late.State != pdpa.Warning {
		t.Fatalf("backdated declaration: %+v %v", late, err)
	}
	if got := findings(t, s, acme, "pdpa_breach"); len(got) != 1 || got[0].Fingerprint != "pdpa_breach:"+late.ID+":warning" {
		t.Fatalf("backdated Findings %+v", got)
	}
	if _, err := svc.Close(ctx, acme, late.ID, " ", lead); !errors.Is(err, pdpa.ErrInvalid) {
		t.Fatalf("close without reason: %v", err)
	}
	if cl, err := svc.Close(ctx, acme, late.ID, "bucket held only synthetic test data", lead); err != nil || cl.State != pdpa.Closed || len(open(findings(t, s, acme, "pdpa_breach"))) != 0 {
		t.Fatalf("close: %+v %v", cl, err)
	}
	future := c.now().Add(time.Hour)
	if _, err := svc.Declare(ctx, tat, pdpa.Declaration{Title: "x", AwareAt: &future}, lead); !errors.Is(err, pdpa.ErrInvalid) {
		t.Fatalf("future awareness: %v", err)
	}
	if _, err := svc.Notify(ctx, acme, b.ID, pdpa.Notification{Reference: "x"}, lead); !errors.Is(err, pdpa.ErrNotFound) {
		t.Fatalf("another Tenant's breach: %v", err)
	}
	storetest.ClockedFindings(t, s, "pdpa_breach")
}

func TestEvidenceExportCarriesEveryPDPAControl(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	c := newClock()
	tat, _ := s.CreateTenant(ctx, "tat", "TAT", false)
	account(t, s, tat, "crm")
	reg, err := controls.Load()
	if err != nil {
		t.Fatal(err)
	}
	svc := pdpa.Service{Store: s, Now: c.now, Stores: []pdpa.Location{{Kind: "archive", Name: "arch", Region: "ap-southeast-1"}}}
	cs := controls.Service{Store: s, Registry: reg}
	gap := func(id string) bool {
		t.Helper()
		rep, err := cs.Report(ctx, tat)
		if err != nil {
			t.Fatal(err)
		}
		for _, v := range rep.Controls {
			if v.Framework == "PDPA" && v.ID == id {
				return v.Gap
			}
		}
		t.Fatalf("no PDPA %s", id)
		return false
	}
	if !gap("s.28") || !gap("s.37(3)") || gap("s.37(4)") {
		t.Fatal("residency and retention are gaps until they run; the breach clock covers every Service")
	}
	if _, err := svc.RunResidency(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RunRetention(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Declare(ctx, tat, pdpa.Declaration{Title: "phished credentials"}, admin); err != nil {
		t.Fatal(err)
	}
	if gap("s.28") || gap("s.37(3)") {
		t.Fatal("residency and retention ran but their Controls are still gaps")
	}

	pub, key, _ := ed25519.GenerateKey(nil)
	from := c.now().AddDate(0, 0, -1)
	bundle, err := evidence.Exporter{Store: s, Controls: cs, PDPA: svc, Key: key, Now: c.now}.Export(ctx, tat, from, from.AddDate(0, 0, 2), admin)
	if err != nil {
		t.Fatal(err)
	}
	if bundle.Manifest.Format != "keel-evidence@1" || evidence.Verify(pub, bundle) != nil {
		t.Fatalf("bundle %s does not verify", bundle.Manifest.Format)
	}
	var sec pdpa.Evidence
	if err := json.Unmarshal(bundle.Sections["pdpa"], &sec); err != nil {
		t.Fatal(err)
	}
	var want []string
	for _, ctl := range reg.Controls {
		if ctl.Framework == "PDPA" {
			want = append(want, ctl.ID)
		}
	}
	if len(want) != len(sec.Controls) || len(want) == 0 {
		t.Fatalf("pdpa section has %d controls, registry %d", len(sec.Controls), len(want))
	}
	for i, ce := range sec.Controls {
		if ce.ID != want[i] || (len(ce.Evidence) == 0) == (ce.GapReason == "") {
			t.Errorf("control %+v: needs evidence or a gap reason, not both", ce)
		}
	}
	if len(sec.Breaches) != 1 || len(sec.Schedule) != len(pdpa.Schedule) || string(sec.RetentionRuns) == "[]" {
		t.Fatalf("pdpa section %s", bundle.Sections["pdpa"])
	}
	var res struct {
		Open []json.RawMessage `json:"open"`
	}
	if err := json.Unmarshal(sec.Residency, &res); err != nil || len(res.Open) != 1 {
		t.Fatalf("residency %s %v", sec.Residency, err)
	}
}
