package clientreads_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/clientreads"
	"github.com/hx-thanadej/keel/internal/cost"
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

type client struct {
	tenant, payer, member, payerAccount, env string
}

type world struct {
	s          *store.Store
	home, tat  string
	c1, c2     client
	keelMember string
}

// setup registers Keel's home Tenant, a platform Tenant with a
// platform-owned AWS account, and two client Tenants, each with a
// client-owned AWS management account (its payer) and member account.
func setup(t *testing.T) world {
	t.Helper()
	ctx := context.Background()
	s := storetest.New(t)
	w := world{s: s, keelMember: "222222222222"}
	var err error
	w.home, err = s.CreateTenant(ctx, "harmonyx", "HarmonyX", true)
	must(t, err)
	w.tat, err = s.CreateTenant(ctx, "tat", "TAT", false)
	must(t, err)
	must(t, s.InTenant(ctx, w.tat, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO cloud_accounts (tenant_id, provider, external_id, name) VALUES ($1, 'aws', $2, 'tat-prod')`, w.tat, w.keelMember)
		return err
	}))
	w.c1 = addClient(t, s, "c1", "300000000001", "300000000011")
	w.c2 = addClient(t, s, "c2", "300000000002", "300000000022")
	return w
}

func addClient(t *testing.T, s *store.Store, slug, payer, member string) client {
	t.Helper()
	ctx := context.Background()
	c := client{payer: payer, member: member}
	var err error
	c.tenant, err = s.CreateTenant(ctx, slug, slug, false)
	must(t, err)
	must(t, s.InTenant(ctx, c.tenant, func(tx pgx.Tx) error {
		var team, project string
		if err := tx.QueryRow(ctx, `INSERT INTO teams (tenant_id, slug, name) VALUES ($1, 'ops', 'Ops') RETURNING id`, c.tenant).Scan(&team); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO projects (tenant_id, team_id, slug, name) VALUES ($1, $2, $3, 'Shop') RETURNING id`, c.tenant, team, slug+"-shop").Scan(&project); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO environments (tenant_id, project_id, name) VALUES ($1, $2, 'prod') RETURNING id`, c.tenant, project).Scan(&c.env); err != nil {
			return err
		}
		role := func(a string) string { return `{"role_arn": "arn:aws:iam::` + a + `:role/KeelReadOnly"}` }
		if err := tx.QueryRow(ctx, `INSERT INTO cloud_accounts (tenant_id, provider, external_id, name, ownership, read_only_role) VALUES ($1, 'aws', $2, 'payer', 'client', $3) RETURNING id`,
			c.tenant, payer, role(payer)).Scan(&c.payerAccount); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO cloud_accounts (tenant_id, environment_id, provider, external_id, name, ownership, read_only_role) VALUES ($1, $2, 'aws', $3, 'shop-prod', 'client', $4)`,
			c.tenant, c.env, member, role(member))
		return err
	}))
	return c
}

func (c client) clientPayer() cost.ClientPayer {
	return cost.ClientPayer{TenantID: c.tenant, CloudAccountID: c.payerAccount, PayerID: c.payer, RoleARN: "arn:aws:iam::" + c.payer + ":role/KeelReadOnly", Region: "us-east-1"}
}

// fake is one payer's cloud as its read-only role sees it.
type fake struct {
	budgets  []clientreads.Budget
	findings []clientreads.Finding
	recs     []rightsize.Recommendation
	fail     map[string]error
}

func (f *fake) Budgets(context.Context) ([]clientreads.Budget, error) {
	return f.budgets, f.fail["budgets"]
}
func (f *fake) Findings(context.Context) ([]clientreads.Finding, error) {
	return f.findings, f.fail["findings"]
}
func (f *fake) Recommendations(context.Context) ([]rightsize.Recommendation, error) {
	return f.recs, f.fail["recommendations"]
}

func rec(account, resource string) rightsize.Recommendation {
	return rightsize.Recommendation{Source: "native:aws_coh", Provider: "aws", AccountID: account, ResourceID: resource, ResourceType: "ec2instance",
		Action: "resize", MonthlySavings: "10.00", Currency: "USD", Confidence: 0.8}
}

type openFinding struct{ kind, fingerprint, severity, env string }

func open(t *testing.T, s *store.Store, tenant string) []openFinding {
	t.Helper()
	ctx := context.Background()
	var out []openFinding
	must(t, s.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT kind, fingerprint, severity, coalesce(environment_id::text, '') FROM findings
			WHERE status = 'open' AND kind IN ('cloud_budget', 'cloud_security') ORDER BY fingerprint`)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (openFinding, error) {
			var f openFinding
			return f, r.Scan(&f.kind, &f.fingerprint, &f.severity, &f.env)
		})
		return err
	}))
	return out
}

func recs(t *testing.T, s *store.Store, tenant string) []string {
	t.Helper()
	list, err := (rightsize.Service{Store: s}).List(context.Background(), tenant, rightsize.Filter{})
	must(t, err)
	var out []string
	for _, r := range list {
		out = append(out, r.AccountID+"/"+r.ResourceID)
	}
	slices.Sort(out)
	return out
}

// TestClientReadsLandOnlyInThePayersTenant: c1's role returns budgets,
// security findings and recommendations, some naming c2's account, Keel's
// platform account and an unregistered account. Only c1's own land, in
// c1's Tenant; the rest are dropped and counted; nothing reaches the home
// Tenant, c2 or the platform Tenant.
func TestClientReadsLandOnlyInThePayersTenant(t *testing.T) {
	w := setup(t)
	ctx := context.Background()
	clouds := map[string]*fake{
		w.c1.payer: {
			budgets: []clientreads.Budget{
				{Name: "org-monthly", Limit: "1000", Actual: "1200.5", Forecast: "1500", Unit: "USD"},
				{Name: "shop", Limit: "500", Actual: "100", Forecast: "600", Unit: "USD"},
				{Name: "fine", Limit: "500", Actual: "100", Forecast: "200", Unit: "USD"},
				{Name: "no-limit", Actual: "100", Unit: "USD"},
			},
			findings: []clientreads.Finding{
				{ID: "arn:sh/f-payer", Account: w.c1.payer, Severity: "critical", Title: "Root has access keys", Source: "Security Hub"},
				{ID: "arn:sh/f-member", Account: w.c1.member, Severity: "medium", Title: "S3 bucket public", Source: "Config", Resource: "arn:aws:s3:::shop"},
				{ID: "arn:sh/f-c2", Account: w.c2.member, Severity: "high", Title: "c2's"},
				{ID: "arn:sh/f-keel", Account: w.keelMember, Severity: "high", Title: "Keel's"},
				{ID: "arn:sh/f-nobody", Account: "399999999999", Severity: "high", Title: "unregistered"},
			},
			recs: []rightsize.Recommendation{rec(w.c1.member, "i-c1"), rec(w.c2.member, "i-c2"), rec(w.keelMember, "i-keel"), rec("399999999999", "i-nobody")},
		},
		w.c2.payer: {recs: []rightsize.Recommendation{rec(w.c2.member, "i-c2-own")}},
	}
	var connected []string
	sync := &clientreads.Sync{Store: w.s, Provider: "aws", Now: func() time.Time { return time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC) },
		Connect: func(p cost.ClientPayer) (clientreads.Reader, error) {
			connected = append(connected, p.PayerID)
			return clouds[p.PayerID], nil
		}}
	reports, err := sync.Run(ctx, []cost.ClientPayer{w.c1.clientPayer(), w.c2.clientPayer()})
	must(t, err)
	if !slices.Equal(connected, []string{w.c1.payer, w.c2.payer}) {
		t.Fatalf("connected %v, want each payer once", connected)
	}
	if len(reports) != 2 || reports[0].Budgets != 4 || reports[0].BudgetsOver != 2 || reports[0].Findings != 2 || reports[0].Recommendations != 1 || reports[0].Dropped != 6 {
		t.Fatalf("reports %+v, want c1: 4 budgets, 2 over, 2 findings, 1 recommendation, 6 dropped", reports)
	}

	want := []openFinding{
		{"cloud_budget", "cloud_budget:aws/" + w.c1.payer + "/org-monthly", "high", ""},
		{"cloud_budget", "cloud_budget:aws/" + w.c1.payer + "/shop", "medium", ""},
		{"cloud_security", "cloud_security:aws/" + w.c1.payer + "/arn:sh/f-member", "medium", w.c1.env},
		{"cloud_security", "cloud_security:aws/" + w.c1.payer + "/arn:sh/f-payer", "critical", ""},
	}
	if got := open(t, w.s, w.c1.tenant); !slices.Equal(got, want) {
		t.Errorf("c1 findings\n got %v\nwant %v", got, want)
	}
	for name, tenant := range map[string]string{"home": w.home, "c2": w.c2.tenant, "tat": w.tat} {
		if got := open(t, w.s, tenant); len(got) != 0 {
			t.Errorf("%s holds client findings %v, want none", name, got)
		}
	}
	if got, want := recs(t, w.s, w.c1.tenant), []string{w.c1.member + "/i-c1"}; !slices.Equal(got, want) {
		t.Errorf("c1 recommendations %v, want %v", got, want)
	}
	if got, want := recs(t, w.s, w.c2.tenant), []string{w.c2.member + "/i-c2-own"}; !slices.Equal(got, want) {
		t.Errorf("c2 recommendations %v, want only its own payer's %v", got, want)
	}
	for name, tenant := range map[string]string{"home": w.home, "tat": w.tat} {
		if got := recs(t, w.s, tenant); len(got) != 0 {
			t.Errorf("%s holds client recommendations %v, want none", name, got)
		}
	}
}

// TestClientReadsResolveWhatIsGoneButNotWhatFailed: a finding no longer
// reported and a budget back under its limit resolve on the next read; a
// source that fails leaves its Findings open and does not stop the others.
func TestClientReadsResolveWhatIsGoneButNotWhatFailed(t *testing.T) {
	w := setup(t)
	ctx := context.Background()
	cloud := &fake{
		budgets: []clientreads.Budget{{Name: "org", Limit: "10", Actual: "20", Forecast: "30", Unit: "USD"}},
		findings: []clientreads.Finding{
			{ID: "f-1", Account: w.c1.payer, Severity: "high", Title: "one"},
			{ID: "f-2", Account: w.c1.payer, Severity: "low", Title: "two"},
		},
	}
	sync := &clientreads.Sync{Store: w.s, Provider: "aws", Connect: func(cost.ClientPayer) (clientreads.Reader, error) { return cloud, nil }}
	_, err := sync.Run(ctx, []cost.ClientPayer{w.c1.clientPayer()})
	must(t, err)
	if got := open(t, w.s, w.c1.tenant); len(got) != 3 {
		t.Fatalf("open %v, want the budget and two findings", got)
	}

	cloud.budgets = []clientreads.Budget{{Name: "org", Limit: "100", Actual: "20", Forecast: "30", Unit: "USD"}}
	cloud.findings = cloud.findings[:1]
	_, err = sync.Run(ctx, []cost.ClientPayer{w.c1.clientPayer()})
	must(t, err)
	if got := open(t, w.s, w.c1.tenant); len(got) != 1 || !strings.HasSuffix(got[0].fingerprint, "/f-1") {
		t.Fatalf("open %v, want only f-1 once f-2 is gone and the budget is back under", got)
	}

	denied := errors.New("AccessDeniedException: securityhub:GetFindings")
	cloud.fail = map[string]error{"findings": denied}
	cloud.findings = nil
	cloud.budgets = []clientreads.Budget{{Name: "org", Limit: "10", Actual: "20", Unit: "USD"}}
	_, err = sync.Run(ctx, []cost.ClientPayer{w.c1.clientPayer()})
	if !errors.Is(err, denied) {
		t.Fatalf("err %v, want the denied read reported", err)
	}
	got := open(t, w.s, w.c1.tenant)
	if len(got) != 2 || got[0].kind != "cloud_budget" || !strings.HasSuffix(got[1].fingerprint, "/f-1") {
		t.Fatalf("open %v, want f-1 kept open by the failed read and the budget raised again", got)
	}
}

// TestClientReadsRoleFailureLandsNothing: a payer whose role cannot be
// assumed reports the error and the next payer is still read.
func TestClientReadsRoleFailureLandsNothing(t *testing.T) {
	w := setup(t)
	ctx := context.Background()
	refused := &cost.RoleError{Err: errors.New("AccessDenied: sts:AssumeRole")}
	sync := &clientreads.Sync{Store: w.s, Provider: "aws", Connect: func(p cost.ClientPayer) (clientreads.Reader, error) {
		if p.PayerID == w.c1.payer {
			return nil, refused
		}
		return &fake{findings: []clientreads.Finding{{ID: "f", Account: w.c2.member, Severity: "high", Title: "c2"}}}, nil
	}}
	_, err := sync.Run(ctx, []cost.ClientPayer{w.c1.clientPayer(), w.c2.clientPayer()})
	if !errors.Is(err, refused) {
		t.Fatalf("err %v, want the role failure", err)
	}
	if got := open(t, w.s, w.c2.tenant); len(got) != 1 {
		t.Errorf("c2 open %v, want its finding despite c1's role failure", got)
	}
}

// openRecs is tenant's open recommendations as account/resource.
func openRecs(t *testing.T, s *store.Store, tenant string) []string {
	t.Helper()
	list, err := (rightsize.Service{Store: s}).List(context.Background(), tenant, rightsize.Filter{State: "open"})
	must(t, err)
	var out []string
	for _, r := range list {
		out = append(out, r.AccountID+"/"+r.ResourceID)
	}
	slices.Sort(out)
	return out
}

// TestClientRecommendationsGoneFromACompleteListingAreWithdrawn: advice the
// payer's provider stops reporting is withdrawn on the next complete read,
// and its Finding resolved. A read that fails, even with some
// recommendations in hand, withdraws nothing. A second payer in the same
// Tenant reporting nothing withdraws none of the first payer's advice.
func TestClientRecommendationsGoneFromACompleteListingAreWithdrawn(t *testing.T) {
	w := setup(t)
	ctx := context.Background()
	second := client{payer: "300000000003", member: "300000000033"}
	must(t, w.s.InTenant(ctx, w.c1.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO cloud_accounts (tenant_id, provider, external_id, name, ownership, read_only_role)
			VALUES ($1, 'aws', $2, 'payer-2', 'client', '{"role_arn": "arn:aws:iam::300000000003:role/KeelReadOnly"}'),
			       ($1, 'aws', $3, 'member-2', 'client', '{"role_arn": "arn:aws:iam::300000000033:role/KeelReadOnly"}')`,
			w.c1.tenant, second.payer, second.member)
		return err
	}))
	second.tenant = w.c1.tenant
	clouds := map[string]*fake{
		w.c1.payer:   {recs: []rightsize.Recommendation{rec(w.c1.member, "i-kept"), rec(w.c1.member, "i-gone"), rec(w.c1.payer, "i-flaky")}},
		second.payer: {recs: []rightsize.Recommendation{rec(second.member, "i-second")}},
	}
	sync := &clientreads.Sync{Store: w.s, Provider: "aws", Listing: "native:aws_coh",
		Connect: func(p cost.ClientPayer) (clientreads.Reader, error) { return clouds[p.PayerID], nil }}
	payers := []cost.ClientPayer{w.c1.clientPayer(), second.clientPayer()}
	_, err := sync.Run(ctx, payers)
	must(t, err)
	all := []string{w.c1.payer + "/i-flaky", w.c1.member + "/i-gone", w.c1.member + "/i-kept", second.member + "/i-second"}
	if got := openRecs(t, w.s, w.c1.tenant); !slices.Equal(got, all) {
		t.Fatalf("open %v, want %v", got, all)
	}

	clouds[w.c1.payer].recs = []rightsize.Recommendation{rec(w.c1.member, "i-kept")}
	clouds[w.c1.payer].fail = map[string]error{"recommendations": errors.New("ThrottlingException on page 2")}
	clouds[second.payer].recs = nil
	clouds[second.payer].fail = map[string]error{"recommendations": errors.New("AccessDeniedException")}
	if _, err := sync.Run(ctx, payers); err == nil {
		t.Fatal("failed reads reported no error")
	}
	if got := openRecs(t, w.s, w.c1.tenant); !slices.Equal(got, all) {
		t.Fatalf("open %v after failed reads, want all of %v kept", got, all)
	}

	clouds[w.c1.payer].fail = nil
	clouds[w.c1.payer].recs = []rightsize.Recommendation{rec(w.c1.member, "i-kept")}
	clouds[second.payer].fail = nil
	_, err = sync.Run(ctx, payers)
	must(t, err)
	if got, want := openRecs(t, w.s, w.c1.tenant), []string{w.c1.member + "/i-kept"}; !slices.Equal(got, want) {
		t.Fatalf("open %v, want %v once both payers' complete listings dropped the rest", got, want)
	}

	clouds[second.payer].recs = []rightsize.Recommendation{rec(second.member, "i-second")}
	_, err = sync.Run(ctx, []cost.ClientPayer{second.clientPayer()})
	must(t, err)
	clouds[second.payer].recs = nil
	_, err = sync.Run(ctx, []cost.ClientPayer{w.c1.clientPayer()})
	must(t, err)
	if got, want := openRecs(t, w.s, w.c1.tenant), []string{w.c1.member + "/i-kept", second.member + "/i-second"}; !slices.Equal(got, want) {
		t.Fatalf("open %v, want %v: c1's listing must not withdraw the second payer's advice", got, want)
	}

	var withdrawn, resolved int
	must(t, w.s.InTenant(ctx, w.c1.tenant, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM recommendations WHERE state = 'superseded' AND decision_reason = 'no longer reported by native:aws_coh'`).Scan(&withdrawn); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT count(*) FROM findings WHERE kind = 'rightsizing' AND status = 'resolved' AND resolution = 'no longer reported by native:aws_coh'`).Scan(&resolved)
	}))
	if withdrawn != 3 || resolved != 3 {
		t.Errorf("withdrawn %d with %d Findings resolved, want 3 and 3", withdrawn, resolved)
	}
}

// TestClientReadsWithoutAListingWithdrawNothing: a provider whose
// Recommendations are not a complete listing (Keel's VM engine for Tencent
// reports only what it could evaluate) never withdraws advice.
func TestClientReadsWithoutAListingWithdrawNothing(t *testing.T) {
	w := setup(t)
	ctx := context.Background()
	cloud := &fake{recs: []rightsize.Recommendation{rec(w.c1.member, "i-1")}}
	sync := &clientreads.Sync{Store: w.s, Provider: "aws", Connect: func(cost.ClientPayer) (clientreads.Reader, error) { return cloud, nil }}
	_, err := sync.Run(ctx, []cost.ClientPayer{w.c1.clientPayer()})
	must(t, err)
	cloud.recs = nil
	_, err = sync.Run(ctx, []cost.ClientPayer{w.c1.clientPayer()})
	must(t, err)
	if got, want := openRecs(t, w.s, w.c1.tenant), []string{w.c1.member + "/i-1"}; !slices.Equal(got, want) {
		t.Errorf("open %v, want %v", got, want)
	}
}
