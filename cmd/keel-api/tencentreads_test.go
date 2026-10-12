package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/clientreads"
	"github.com/hx-thanadej/keel/internal/cost"
	"github.com/hx-thanadej/keel/internal/rightsize"
	"github.com/hx-thanadej/keel/internal/utilisation"
)

// TestClientReadsCoverTencent: production runs the Tencent client reads
// after the Tencent client bill sync, whatever Keel's AWS identity.
func TestClientReadsCoverTencent(t *testing.T) {
	c := newClientWorld(t, "tencent")
	if r := clientReads(context.Background(), c.st)["tencent"]; r == nil || r.Provider != "tencent" {
		t.Fatalf("client reads %v have no Tencent sync", r)
	}
}

// fakeTencentAPI is Tencent as client payer 300000000001's role sees it:
// STS, one budget over its limit, one Smart Advisor risk, quiet Cloud
// Monitor data and the payer instance's type, plus Tencent's CVM catalogue.
// Any other action is refused and recorded.
type fakeTencentAPI struct {
	mu        sync.Mutex
	calls     []string // action and the SecretId that signed it
	assumed   []map[string]any
	monitored []string
	described []string
	overspent bool
	risky     bool
}

func (f *fakeTencentAPI) set(overspent, risky bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.overspent, f.risky, f.calls, f.monitored = overspent, risky, nil, nil
}

func (f *fakeTencentAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	action := r.Header.Get("X-TC-Action")
	raw, _ := io.ReadAll(r.Body)
	var body map[string]any
	_ = json.Unmarshal(raw, &body)
	signer, _, _ := strings.Cut(strings.TrimPrefix(r.Header.Get("Authorization"), "TC3-HMAC-SHA256 Credential="), "/")
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, action+" "+signer)
	switch action {
	case "GetCallerIdentity":
		_, _ = io.WriteString(w, `{"Response":{"Arn":"qcs::sts:200000000001:assumed-role/4611686018427397919/keel","AccountId":"200000000001","Type":"AssumedRole","RequestId":"r"}}`)
	case "AssumeRole":
		f.assumed = append(f.assumed, body)
		_, _ = io.WriteString(w, `{"Response":{"Credentials":{"TmpSecretId":"session-id","TmpSecretKey":"k","Token":"t"},"ExpiredTime":4102444800,"RequestId":"r"}}`)
	case "DescribeBudget":
		spent := "400.00"
		if f.overspent {
			spent = "1250.50"
		}
		_, _ = io.WriteString(w, `{"Response":{"Data":{"Records":[{"BudgetName":"org-monthly","PlanType":"FIX","BudgetQuota":"1000","RealCost":"`+spent+`","BudgetStatus":"ACTIVE"}]},"RequestId":"r"}}`)
	case "DescribeStrategies":
		_, _ = io.WriteString(w, `{"Response":{"Strategies":[{"StrategyId":9,"Name":"Security group open to all","GroupName":"Security","ProductDesc":"CVM","Conditions":[{"Level":3}]}],"RequestId":"r"}}`)
	case "DescribeTaskStrategyRisks":
		risks := `[]`
		if f.risky {
			risks = `[{\"InstanceId\":\"ins-payer\",\"Level\":3}]`
		}
		_, _ = io.WriteString(w, `{"Response":{"StrategyId":9,"RiskFieldsDesc":[{"Field":"InstanceId","FieldName":"ID","FieldType":"string"}],"Risks":"`+risks+`","RequestId":"r"}}`)
	case "GetMonitorData":
		value := 10.0
		if body["MetricName"] == "MemUsage" {
			value = 20
		}
		var points []string
		for _, in := range body["Instances"].([]any) {
			id := in.(map[string]any)["Dimensions"].([]any)[0].(map[string]any)["Value"].(string)
			f.monitored = append(f.monitored, id)
			points = append(points, fmt.Sprintf(`{"Dimensions":[{"Name":"InstanceId","Value":%q}],"Values":[%g,%g,%g]}`, id, value, value, value))
		}
		_, _ = io.WriteString(w, `{"Response":{"DataPoints":[`+strings.Join(points, ",")+`],"RequestId":"r"}}`)
	case "DescribeInstances":
		for _, id := range body["InstanceIds"].([]any) {
			f.described = append(f.described, id.(string))
		}
		_, _ = io.WriteString(w, `{"Response":{"InstanceSet":[{"InstanceId":"ins-payer","InstanceType":"S5.2XLARGE16"}],"TotalCount":1,"RequestId":"r"}}`)
	case "DescribeZoneInstanceConfigInfos":
		_, _ = io.WriteString(w, `{"Response":{"InstanceTypeQuotaSet":[`+
			`{"InstanceType":"S5.2XLARGE16","InstanceFamily":"S5","Cpu":8,"Memory":16,"Status":"SELL","Price":{"UnitPrice":0.20}},`+
			`{"InstanceType":"S5.MEDIUM4","InstanceFamily":"S5","Cpu":2,"Memory":4,"Status":"SELL","Price":{"UnitPrice":0.05}}],"RequestId":"r"}}`)
	default:
		_, _ = io.WriteString(w, `{"Response":{"Error":{"Code":"UnauthorizedOperation","Message":"unexpected"},"RequestId":"r"}}`)
	}
}

func (f *fakeTencentAPI) snapshot() (calls, monitored []string, assumed []map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls), slices.Clone(f.monitored), slices.Clone(f.assumed)
}

func (f *fakeTencentAPI) describedInstances() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.described)
}

// tencentReadsWorld is a client Tenant whose Tencent payer 300000000001 ran
// CVM ins-payer and whose registered member account 300000000011 ran
// ins-member, each for 2.00 USD a day over the last month.
func tencentReadsWorld(t *testing.T) (clientWorld, cost.ClientPayer) {
	t.Helper()
	ctx := context.Background()
	c := newClientWorld(t, "tencent")
	p := cost.ClientPayer{TenantID: c.tenant, CloudAccountID: c.account, PayerID: c.payer, RoleARN: payerShapes["tencent"].role, Region: "ap-bangkok"}
	if err := c.st.InTenant(ctx, c.tenant, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT role_external_id FROM client_payers WHERE cloud_account_id = $1`, c.account).Scan(&p.RoleExternalID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO cloud_accounts (tenant_id, provider, external_id, name, ownership, read_only_role)
			VALUES ($1, 'tencent', '300000000011', 'member', 'client', '{"role_arn": "qcs::cam::uin/300000000011:roleName/KeelReadOnly"}')`, c.tenant)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	today := time.Now().UTC().Truncate(24 * time.Hour)
	byPeriod := map[time.Time][]cost.Line{}
	for d := today.AddDate(0, 0, -30); d.Before(today); d = d.AddDate(0, 0, 1) {
		period := time.Date(d.Year(), d.Month(), 1, 0, 0, 0, 0, time.UTC)
		for acct, ins := range map[string]string{c.payer: "ins-payer", "300000000011": "ins-member"} {
			byPeriod[period] = append(byPeriod[period], cost.Line{SubAccountID: acct, BillingPeriodStart: period, ChargePeriodStart: d, ChargePeriodEnd: d.AddDate(0, 0, 1),
				ChargeCategory: "Usage", BilledCost: "2.00", BillingCurrency: "USD", ServiceName: "Cloud Virtual Machine", ResourceID: ins, Tags: map[string]string{}, Vendor: map[string]string{}})
		}
	}
	for period, lines := range byPeriod {
		if _, err := (&cost.Ingester{Store: c.st}).Load(ctx, cost.Load{Provider: "tencent", BillingAccountID: c.payer, BillingPeriod: period, Lines: lines, Tenant: c.tenant}); err != nil {
			t.Fatal(err)
		}
	}
	// The member instance's utilisation is on record, as if collected before
	// the account moved to the client; Keel still holds no session there.
	var sums []utilisation.Summary
	for i := 1; i <= 14; i++ {
		sums = append(sums, utilisation.Summary{Provider: "tencent", ResourceID: "ins-member", ResourceType: "vm", Metric: "cpu_pct", Day: today.AddDate(0, 0, -i), P95: 5, Max: 6, Samples: 1440})
	}
	if err := (utilisation.Store{Store: c.st}).Save(ctx, c.tenant, nil, nil, sums); err != nil {
		t.Fatal(err)
	}
	return c, p
}

// TestTencentClientReadsThroughTheReadOnlyRole: the production Tencent
// client reads assume the payer's role from Keel's identity with the
// payer's ExternalId and a session policy allowing only the five read
// actions; every client read is signed by that session and only the CVM
// catalogue by Keel. The payer's budget overrun, its Smart Advisor risk and
// a rightsizing of its own instance land in its Tenant only; the member
// account's instance is never read. A second run changes nothing, and once
// the budget and the risk clear their Findings resolve.
func TestTencentClientReadsThroughTheReadOnlyRole(t *testing.T) {
	c, payer := tencentReadsWorld(t)
	ctx := context.Background()
	api := &fakeTencentAPI{}
	srv := httptest.NewServer(api)
	defer srv.Close()
	reads := tencentClientReads(c.st, staticCreds{id: "base-id"}, srv.URL, srv.URL)

	api.set(true, true)
	reports, err := reads.Run(ctx, []cost.ClientPayer{payer})
	if err != nil {
		t.Fatalf("reads: %v", err)
	}
	calls, monitored, assumed := api.snapshot()
	if len(assumed) != 1 || assumed[0]["ExternalId"] != payer.RoleExternalID || assumed[0]["RoleArn"] != payer.RoleARN {
		t.Fatalf("AssumeRole %v, want one for the payer's role with its ExternalId", assumed)
	}
	policy, _ := url.QueryUnescape(fmt.Sprint(assumed[0]["Policy"]))
	if want := `{"version":"2.0","statement":[{"effect":"allow","action":["finance:DescribeBudget","advisor:DescribeStrategies","advisor:DescribeTaskStrategyRisks","monitor:GetMonitorData","cvm:DescribeInstances"],"resource":["*"]}]}`; policy != want {
		t.Errorf("session policy %s, want %s", policy, want)
	}
	allowed := map[string]bool{"AssumeRole base-id": true, "DescribeZoneInstanceConfigInfos base-id": true, "DescribeBudget session-id": true,
		"DescribeStrategies session-id": true, "DescribeTaskStrategyRisks session-id": true, "GetMonitorData session-id": true, "DescribeInstances session-id": true}
	for _, call := range calls {
		if !allowed[call] {
			t.Errorf("Tencent call %q is not one of the reads, or is signed by the wrong identity", call)
		}
	}
	if slices.ContainsFunc(monitored, func(id string) bool { return id != "ins-payer" }) || len(monitored) == 0 {
		t.Errorf("Cloud Monitor asked about %v, want only the payer's ins-payer", monitored)
	}
	if got := api.describedInstances(); !slices.Equal(got, []string{"ins-payer"}) {
		t.Errorf("DescribeInstances asked about %v, want only the payer's ins-payer", got)
	}
	got := openKinds(t, c, c.tenant)
	wantOpen := []string{"cloud_budget high cloud_budget:tencent/300000000001/org-monthly", "cloud_security high cloud_security:tencent/300000000001/9/ins-payer"}
	if len(got) != 3 || !slices.Equal(got[:2], wantOpen) || !strings.HasPrefix(got[2], "rightsizing ") {
		t.Fatalf("client Tenant Findings %v, want %v and one rightsizing Finding", got, wantOpen)
	}
	list, err := (rightsize.Service{Store: c.st}).List(ctx, c.tenant, rightsize.Filter{State: "open"})
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].AccountID != c.payer || list[0].ResourceID != "ins-payer" || list[0].Recommended["instance_type"] != "S5.MEDIUM4" {
		t.Errorf("client Recommendations %+v, want ins-payer down to S5.MEDIUM4", list)
	}
	if got := openKinds(t, c, c.home); len(got) != 0 {
		t.Errorf("home Tenant Findings %v, want none from a client's cloud", got)
	}
	if r := reports[0]; r.BudgetsOver != 1 || r.Findings != 1 || r.Recommendations != 1 || r.Dropped != 0 {
		t.Errorf("report %+v", r)
	}

	if _, err := reads.Run(ctx, []cost.ClientPayer{payer}); err != nil {
		t.Fatalf("second read: %v", err)
	}
	if again := openKinds(t, c, c.tenant); !slices.Equal(again, got) {
		t.Errorf("second run Findings %v, want unchanged %v", again, got)
	}

	api.set(false, false)
	if _, err := reads.Run(ctx, []cost.ClientPayer{payer}); err != nil {
		t.Fatalf("cleared read: %v", err)
	}
	if left := openKinds(t, c, c.tenant); len(left) != 1 || !strings.HasPrefix(left[0], "rightsizing ") {
		t.Errorf("Findings after the budget and risk cleared %v, want only the rightsizing one", left)
	}
}

// TestTencentClientReadsWaitForKeelsIdentity: when STS rejects Keel's own
// Tencent identity, the bill sync stops before any client role and so do
// the reads: no AssumeRole, no read, nothing in the client's Tenant.
func TestTencentClientReadsWaitForKeelsIdentity(t *testing.T) {
	c, _ := tencentReadsWorld(t)
	ctx := context.Background()
	fake := &fakeSTS{provider: "tencent"}
	fake.set(false, true)
	api := &fakeTencentAPI{}
	stsSrv, apiSrv := httptest.NewServer(fake), httptest.NewServer(api)
	defer stsSrv.Close()
	defer apiSrv.Close()

	syncClients(ctx, []*cost.ClientBillSync{tencentClientBillSync(&cost.Ingester{Store: c.st}, staticCreds{id: "base-id"}, stsSrv.URL)},
		map[string]*clientreads.Sync{"tencent": tencentClientReads(c.st, staticCreds{id: "base-id"}, apiSrv.URL, apiSrv.URL)})

	if got := fake.calls(); !slices.Equal(got, []string{"GetCallerIdentity"}) {
		t.Errorf("STS calls %v, want only Keel's own identity check", got)
	}
	if calls, _, _ := api.snapshot(); len(calls) != 0 {
		t.Errorf("Tencent calls %v with Keel's identity rejected", calls)
	}
	if got := openKinds(t, c, c.tenant); len(got) != 0 {
		t.Errorf("client Tenant Findings %v, want none", got)
	}
}

// TestPlatformVMEngineSkipsClientAccounts: Keel's own VM engine, which
// reads instance types through Keel's member roles, never asks about a
// client-owned account's instances, even with their utilisation stored.
func TestPlatformVMEngineSkipsClientAccounts(t *testing.T) {
	c, payer := tencentReadsWorld(t)
	ctx := context.Background()
	api := &fakeTencentAPI{}
	srv := httptest.NewServer(api)
	defer srv.Close()
	api.set(false, false)
	if _, err := tencentClientReads(c.st, staticCreds{id: "base-id"}, srv.URL, srv.URL).Run(ctx, []cost.ClientPayer{payer}); err != nil {
		t.Fatal(err)
	}
	var asked []string
	engine := rightsize.VMEngine{Service: rightsize.Service{Store: c.st}, Catalog: clientCatalog{}, Region: "ap-bangkok",
		Inventory: func(account string) rightsize.Inventory {
			asked = append(asked, account)
			return failingInventory{fmt.Errorf("no member role in %s", account)}
		}}
	res, err := engine.Run(ctx)
	if err != nil {
		t.Fatalf("platform engine: %v", err)
	}
	if len(asked) != 0 || res.Skipped["other_ownership"] == 0 {
		t.Errorf("platform engine asked %v for instance types (result %+v), want no client account", asked, res)
	}
}

type clientCatalog struct{}

func (clientCatalog) Types(context.Context, string) ([]rightsize.InstanceType, error) {
	return []rightsize.InstanceType{{Name: "S5.2XLARGE16", Family: "S5", CPU: 8, MemoryGiB: 16, HourlyPrice: 0.2}}, nil
}
