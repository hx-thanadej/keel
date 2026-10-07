package cost_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/cost"
)

var sep1 = time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)

func line(sub, svc, res, billed string, tags map[string]string) cost.Line {
	if tags == nil {
		tags = map[string]string{}
	}
	return cost.Line{SubAccountID: sub, BillingPeriodStart: sep1, ChargePeriodStart: sep1, ChargePeriodEnd: sep1.AddDate(0, 0, 1),
		ChargeCategory: "Usage", BilledCost: billed, BillingCurrency: "USD", ServiceName: svc, ResourceID: res, Tags: tags, Vendor: map[string]string{}}
}

// sharedWorld adds a home project "keel" and a platform-owned account "shared-uin".
func sharedWorld(t *testing.T) (world, string) {
	w := setup(t)
	var keel string
	must(t, w.s.InTenant(context.Background(), w.home, func(tx pgx.Tx) error {
		var team string
		if err := tx.QueryRow(context.Background(), `SELECT id FROM teams LIMIT 1`).Scan(&team); err != nil {
			return err
		}
		if err := tx.QueryRow(context.Background(), `INSERT INTO projects (tenant_id, team_id, slug, name) VALUES ($1, $2, 'keel', 'Keel') RETURNING id`, w.home, team).Scan(&keel); err != nil {
			return err
		}
		_, err := tx.Exec(context.Background(), `INSERT INTO cloud_accounts (tenant_id, environment_id, provider, external_id, name) VALUES ($1, NULL, 'tencent', 'shared-uin', 'platform-shared')`, w.home)
		return err
	}))
	return w, keel
}

func loadLines(t *testing.T, w world, lines ...cost.Line) cost.LoadResult {
	t.Helper()
	res, err := (&cost.Ingester{Store: w.s}).Load(context.Background(), cost.Load{Provider: "tencent", BillingAccountID: "payer", BillingPeriod: sep1, Lines: lines})
	must(t, err)
	return res
}

func scopeSum(t *testing.T, w world, tenant, method string) string {
	t.Helper()
	return sum(t, w, tenant, "allocation_method = $1", method)
}

func TestScopeTagAllocatesUnknownAccount(t *testing.T) {
	w, _ := sharedWorld(t)
	res := loadLines(t, w,
		line("mystery", "Cloud Object Storage", "b1", "5.00", map[string]string{"keel-scope": "tat/tat-crm/dev"}),
		line("mystery", "Cloud Object Storage", "b2", "2.00", map[string]string{"keel-scope": "tat/no-such-project/dev"}),
	)
	if res.Unallocated != 1 {
		t.Fatalf("result %+v", res)
	}
	if got := sum(t, w, w.tat, "environment_id = $1 AND allocation_method = 'tag'", w.devEnv); got != "5.00" {
		t.Errorf("tag-allocated dev = %s", got)
	}
	if got := scopeSum(t, w, w.home, "unallocated"); got != "2.00" {
		t.Errorf("bad scope stays unallocated: %s", got)
	}
}

func TestWeightRuleSplitsSharedAccountExactly(t *testing.T) {
	w, keel := sharedWorld(t)
	rules := cost.Rules{Store: w.s}
	_, err := rules.Create(context.Background(), w.home, cost.Rule{Provider: "tencent", SubAccountID: "shared-uin", ServiceName: "Tencent Container Registry",
		Kind: "weights", Shares: []cost.Share{{ProjectID: w.project, EnvironmentID: &w.prdEnv, Weight: "2"}, {ProjectID: keel, Weight: "1"}}})
	must(t, err)
	loadLines(t, w,
		line("shared-uin", "Tencent Container Registry", "tcr-1", "10.00", nil),
		line("shared-uin", "Cloud Log Service", "cls-1", "3.00", nil), // no rule: stays platform
	)
	if got := sum(t, w, w.tat, "allocation_method = 'rule'"); got != "6.666667" {
		t.Errorf("TAT share = %s, want 6.666667", got)
	}
	if got := sum(t, w, w.home, "allocation_method = 'rule'"); got != "3.333333" {
		t.Errorf("home share = %s, want 3.333333 (remainder keeps the total exact)", got)
	}
	if got := sum(t, w, w.home, "allocation_method = 'account' AND project_id IS NULL"); got != "3.00" {
		t.Errorf("unmatched platform spend = %s", got)
	}
}

func TestK8sRuleSplitsByNamespaceShare(t *testing.T) {
	w, keel := sharedWorld(t)
	rules := cost.Rules{Store: w.s}
	_, err := rules.Create(context.Background(), w.home, cost.Rule{Provider: "tencent", SubAccountID: "shared-uin", ServiceName: "Cloud Virtual Machine", Kind: "k8s", Cluster: "shared-tke"})
	must(t, err)
	must(t, rules.MapNamespace(context.Background(), w.home, "shared-tke", "tat-crm-prod", w.project, &w.prdEnv))
	must(t, rules.MapNamespace(context.Background(), w.home, "shared-tke", "keel", keel, nil))
	_, err = rules.SaveNamespaceCosts(context.Background(), w.home, "shared-tke", sep1, map[string]float64{"tat-crm-prod": 30, "keel": 10, "kube-system": 10})
	must(t, err)
	loadLines(t, w, line("shared-uin", "Cloud Virtual Machine", "node-1", "100.00", nil))
	// 30/50 → TAT prod, 10/50 → keel, 10/50 (kube-system, unmapped) stays platform.
	if got := sum(t, w, w.tat, "allocation_method = 'k8s' AND environment_id = $1", w.prdEnv); got != "60.000000" {
		t.Errorf("TAT k8s = %s", got)
	}
	if got := sum(t, w, w.home, "allocation_method = 'k8s' AND project_id = $1", keel); got != "20.000000" {
		t.Errorf("keel k8s = %s", got)
	}
	if got := sum(t, w, w.home, "allocation_method = 'k8s' AND project_id IS NULL"); got != "20.000000" {
		t.Errorf("unmapped namespaces = %s", got)
	}
}

func TestK8sRuleWithoutShareDataLeavesCostOnPlatform(t *testing.T) {
	w, _ := sharedWorld(t)
	_, err := (cost.Rules{Store: w.s}).Create(context.Background(), w.home, cost.Rule{Provider: "tencent", SubAccountID: "shared-uin", Kind: "k8s", Cluster: "shared-tke"})
	must(t, err)
	loadLines(t, w, line("shared-uin", "Cloud Virtual Machine", "node-1", "100.00", nil))
	if got := sum(t, w, w.home, "allocation_method = 'account'"); got != "100.00" {
		t.Errorf("no shares yet: platform keeps %s", got)
	}
}

func TestParseOpenCostAllocation(t *testing.T) {
	// Shape of GET /allocation?window=…&aggregate=namespace&step=1d.
	raw := `{"code":200,"status":"success","data":[
		{"keel":{"name":"keel","window":{"start":"2026-09-01T00:00:00Z","end":"2026-09-02T00:00:00Z"},"totalCost":10.5},
		 "tat-crm-prod":{"name":"tat-crm-prod","window":{"start":"2026-09-01T00:00:00Z","end":"2026-09-02T00:00:00Z"},"totalCost":31.5},
		 "__idle__":{"name":"__idle__","window":{"start":"2026-09-01T00:00:00Z","end":"2026-09-02T00:00:00Z"},"totalCost":8}},
		{"keel":{"name":"keel","window":{"start":"2026-09-02T00:00:00Z","end":"2026-09-03T00:00:00Z"},"totalCost":11}}]}`
	days, err := cost.ParseOpenCost([]byte(raw))
	must(t, err)
	if len(days) != 2 || days[sep1]["tat-crm-prod"] != 31.5 || days[sep1]["__idle__"] != 8 || days[sep1.AddDate(0, 0, 1)]["keel"] != 11 {
		t.Fatalf("parsed %v", days)
	}
}

func TestSplitsConserveTheTotalExactly(t *testing.T) {
	w, keel := sharedWorld(t)
	_, err := (cost.Rules{Store: w.s}).Create(context.Background(), w.home, cost.Rule{Provider: "tencent", SubAccountID: "shared-uin", Kind: "weights",
		Shares: []cost.Share{{ProjectID: w.project, EnvironmentID: &w.prdEnv, Weight: "1"}, {ProjectID: w.project, EnvironmentID: &w.devEnv, Weight: "1"}, {ProjectID: keel, Weight: "1"}}})
	must(t, err)
	loadLines(t, w, line("shared-uin", "Cloud Log Service", "cls", "10.00", nil))
	tat, home := sum(t, w, w.tat, "allocation_method = 'rule'"), sum(t, w, w.home, "allocation_method = 'rule'")
	if tat != "6.666666" || home != "3.333334" { // 3.333333 + 3.333333 + remainder 3.333334 = 10
		t.Fatalf("tat %s home %s, want 6.666666 + 3.333334 = 10", tat, home)
	}
}

func TestRuleValidation(t *testing.T) {
	w, _ := sharedWorld(t)
	r := cost.Rules{Store: w.s}
	bad := []cost.Rule{
		{Provider: "tencent", SubAccountID: "x", Kind: "weights"},
		{Provider: "tencent", SubAccountID: "x", Kind: "k8s"},
		{Provider: "tencent", SubAccountID: "x", Kind: "weights", Shares: []cost.Share{{ProjectID: w.project, Weight: "0"}}},
		{Provider: "tencent", SubAccountID: "x", Kind: "weights", Shares: []cost.Share{{ProjectID: "00000000-0000-4000-8000-000000000000", Weight: "1"}}},
		{Provider: "tencent", SubAccountID: "x", Kind: "nope"},
	}
	for i, b := range bad {
		if _, err := r.Create(context.Background(), w.home, b); err == nil {
			t.Errorf("rule %d accepted", i)
		}
	}
	ok := cost.Rule{Provider: "tencent", SubAccountID: "x", Kind: "k8s", Cluster: "c"}
	if _, err := r.Create(context.Background(), w.home, ok); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Create(context.Background(), w.home, ok); err == nil {
		t.Error("duplicate rule accepted")
	}
}
