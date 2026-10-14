package tencent_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"

	billing "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/billing/v20180709"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"

	"github.com/hx-thanadej/keel/internal/catalog"
	"github.com/hx-thanadej/keel/internal/catalog/catalogtest"
	"github.com/hx-thanadej/keel/internal/clientreads"
	"github.com/hx-thanadej/keel/internal/cloud/tencent"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

type keelCreds struct{}

func (keelCreds) GetCredential() (common.CredentialIface, error) {
	return common.NewTokenCredential("base-id", "base-key", "base-token"), nil
}

// fakeTencent answers STS AssumeRole and the Smart Advisor reads, and
// records each action with its JSON body.
type fakeTencent struct {
	mu      sync.Mutex
	actions []string
	bodies  map[string][]map[string]any
}

func (f *fakeTencent) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	action := r.Header.Get("X-TC-Action")
	raw, _ := io.ReadAll(r.Body)
	var body map[string]any
	_ = json.Unmarshal(raw, &body)
	f.mu.Lock()
	f.actions = append(f.actions, action)
	if f.bodies == nil {
		f.bodies = map[string][]map[string]any{}
	}
	f.bodies[action] = append(f.bodies[action], body)
	f.mu.Unlock()
	switch action {
	case "AssumeRole":
		_, _ = io.WriteString(w, `{"Response":{"Credentials":{"TmpSecretId":"session-id","TmpSecretKey":"k","Token":"t"},"ExpiredTime":4102444800,"RequestId":"r"}}`)
	case "DescribeStrategies":
		_, _ = io.WriteString(w, `{"Response":{"Strategies":[`+
			`{"StrategyId":9,"Name":"CVM security group open to the internet","GroupName":"Security","ProductDesc":"CVM","Conditions":[{"Level":2},{"Level":3}]},`+
			`{"StrategyId":12,"Name":"CLB without backends","GroupName":"Cost","ProductDesc":"CLB","Conditions":[{"Level":2}]}],"RequestId":"r"}}`)
	case "DescribeTaskStrategyRisks":
		if body["StrategyId"] == float64(9) {
			_, _ = io.WriteString(w, `{"Response":{"StrategyId":9,"RiskFieldsDesc":[{"Field":"InstanceId","FieldName":"ID","FieldType":"string"},{"Field":"Level","FieldName":"Level","FieldType":"int"}],`+
				`"RiskTotalCount":2,"Risks":"[{\"InstanceId\":\"ins-a\",\"Level\":3},{\"InstanceId\":\"ins-b\",\"Level\":2}]","RequestId":"r"}}`)
			return
		}
		_, _ = io.WriteString(w, `{"Response":{"StrategyId":12,"RiskFieldsDesc":[{"Field":"LoadBalancerId","FieldName":"ID","FieldType":"string"}],`+
			`"RiskTotalCount":1,"Risks":"[{\"LoadBalancerId\":\"lb-1\"}]","RequestId":"r"}}`)
	default:
		_, _ = io.WriteString(w, `{"Response":{"Error":{"Code":"UnsupportedOperation","Message":"unexpected"},"RequestId":"r"}}`)
	}
}

// TestReadsRoleLimitsTheSession: the reads role is assumed with the
// payer's ExternalId and a URL-encoded session policy that allows exactly
// the five read actions, none of them a write.
func TestReadsRoleLimitsTheSession(t *testing.T) {
	f := &fakeTencent{}
	srv := httptest.NewServer(f)
	defer srv.Close()
	_, grant := catalogtest.ClientPayer(t, storetest.New(t), "tencent", "300000000001", "qcs::cam::uin/300000000001:roleName/KeelReadOnly")
	role, err := tencent.ReadsRole(keelCreds{}, grant, "ap-bangkok", srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := role.GetCredential(); err != nil {
		t.Fatal(err)
	}
	got := f.bodies["AssumeRole"]
	if len(got) != 1 || got[0]["ExternalId"] != grant.ExternalID() {
		t.Fatalf("AssumeRole bodies %v, want one with the payer's ExternalId", got)
	}
	encoded, _ := got[0]["Policy"].(string)
	policy, err := url.QueryUnescape(encoded)
	if err != nil || encoded == policy {
		t.Fatalf("Policy %q is not URL-encoded (%v)", encoded, err)
	}
	var doc struct {
		Version   string
		Statement []struct {
			Effect   string
			Action   []string
			Resource []string
		}
	}
	if err := json.Unmarshal([]byte(policy), &doc); err != nil {
		t.Fatalf("session policy %s: %v", policy, err)
	}
	want := []string{"finance:DescribeBudget", "advisor:DescribeStrategies", "advisor:DescribeTaskStrategyRisks", "monitor:GetMonitorData", "cvm:DescribeInstances"}
	if doc.Version != "2.0" || len(doc.Statement) != 1 || doc.Statement[0].Effect != "allow" || !slices.Equal(doc.Statement[0].Action, want) {
		t.Fatalf("session policy %s, want one allow of %v", policy, want)
	}
	for _, a := range doc.Statement[0].Action {
		verb := a[strings.Index(a, ":")+1:]
		if !strings.HasPrefix(verb, "Describe") && !strings.HasPrefix(verb, "Get") {
			t.Errorf("session policy allows %s, which is not a read", a)
		}
	}
	if _, err := tencent.ReadsRole(keelCreds{}, catalog.ClientReadRole{}, "ap-bangkok", srv.URL); err == nil {
		t.Error("a reads role no registration holds was accepted")
	}
}

func TestBudgetFromTencent(t *testing.T) {
	fixed := tencent.BudgetFromTencent(&billing.BudgetExtend{BudgetName: common.StringPtr("org"), PlanType: common.StringPtr("FIX"),
		BudgetQuota: common.StringPtr("1000"), RealCost: common.StringPtr("1250.50"), ForecastCost: common.StringPtr("1900")})
	if fixed != (clientreads.Budget{Name: "org", Limit: "1000", Actual: "1250.50", Forecast: "1900", Unit: "USD"}) {
		t.Errorf("fixed budget %+v", fixed)
	}
	cycle := tencent.BudgetFromTencent(&billing.BudgetExtend{BudgetName: common.StringPtr("plan"), PlanType: common.StringPtr("CYCLE"),
		CurDateDesc: common.StringPtr("2026-10-12"), RealCost: common.StringPtr("80"),
		BudgetQuotaJson: []*billing.BudgetPlan{{DateDesc: common.StringPtr("2026-09"), Quota: common.StringPtr("50")}, {DateDesc: common.StringPtr("2026-10"), Quota: common.StringPtr("100")}}})
	if cycle.Limit != "100" || cycle.Actual != "80" || cycle.Forecast != "" {
		t.Errorf("planned budget %+v, want October's quota 100", cycle)
	}
}

// TestClientReadsFindingsFromSmartAdvisor: every assessment item's risky
// instances become findings on the payer, with the risk's own level, or
// the item's worst level when the risk has none.
func TestClientReadsFindingsFromSmartAdvisor(t *testing.T) {
	f := &fakeTencent{}
	srv := httptest.NewServer(f)
	defer srv.Close()
	r, err := tencent.NewClientReads(keelCreds{}, "300000000001", "ap-bangkok", srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	got, err := r.Findings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := []clientreads.Finding{
		{ID: "9/ins-a", Account: "300000000001", Severity: "high", Title: "CVM security group open to the internet", Source: "Smart Advisor Security CVM", Resource: "ins-a"},
		{ID: "9/ins-b", Account: "300000000001", Severity: "medium", Title: "CVM security group open to the internet", Source: "Smart Advisor Security CVM", Resource: "ins-b"},
		{ID: "12/lb-1", Account: "300000000001", Severity: "medium", Title: "CLB without backends", Source: "Smart Advisor Cost CLB", Resource: "lb-1"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("findings\n got %+v\nwant %+v", got, want)
	}
	if want := []string{"DescribeStrategies", "DescribeTaskStrategyRisks", "DescribeTaskStrategyRisks"}; !slices.Equal(f.actions, want) {
		t.Errorf("actions %v, want %v", f.actions, want)
	}
}
