package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/clientreads"
	"github.com/hx-thanadej/keel/internal/cost"
)

// fakeAWSAPI answers the three client reads for management account
// 300000000001: one budget over its limit, and a finding and a
// recommendation on the payer and on an account registered nowhere. Any
// other operation is refused and recorded.
type fakeAWSAPI struct {
	mu      sync.Mutex
	ops     []string
	signers []string
}

func (f *fakeAWSAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	op := r.Header.Get("X-Amz-Target")
	if op == "" {
		op = r.Method + " " + r.URL.Path
	}
	f.mu.Lock()
	f.ops = append(f.ops, op)
	f.signers = append(f.signers, r.Header.Get("Authorization"))
	f.mu.Unlock()
	switch op {
	case "AWSBudgetServiceGateway.DescribeBudgets":
		_, _ = io.WriteString(w, `{"Budgets":[{"BudgetName":"org-monthly","BudgetType":"COST","TimeUnit":"MONTHLY",`+
			`"BudgetLimit":{"Amount":"1000.0","Unit":"USD"},"CalculatedSpend":{"ActualSpend":{"Amount":"1250.5","Unit":"USD"},"ForecastedSpend":{"Amount":"1900","Unit":"USD"}}}]}`)
	case "POST /findings":
		_, _ = io.WriteString(w, `{"Findings":[`+
			`{"SchemaVersion":"2018-10-08","Id":"arn:aws:securityhub:us-east-1:300000000001:finding/f-1","ProductArn":"arn:aws:securityhub:us-east-1::product/aws/securityhub","GeneratorId":"g","AwsAccountId":"300000000001",`+
			`"Types":["Software and Configuration Checks"],"CreatedAt":"2026-09-01T00:00:00Z","UpdatedAt":"2026-09-01T00:00:00Z","Severity":{"Label":"CRITICAL"},"Title":"Root user has access keys","Description":"d",`+
			`"ProductName":"Security Hub","Resources":[{"Type":"AwsAccount","Id":"AWS::::Account:300000000001"}]},`+
			`{"SchemaVersion":"2018-10-08","Id":"f-nobody","ProductArn":"p","GeneratorId":"g","AwsAccountId":"399999999999","Types":["t"],"CreatedAt":"2026-09-01T00:00:00Z","UpdatedAt":"2026-09-01T00:00:00Z",`+
			`"Severity":{"Label":"HIGH"},"Title":"elsewhere","Description":"d","ProductName":"Config","Resources":[{"Type":"Other","Id":"x"}]}]}`)
	case "CostOptimizationHubService.ListRecommendations":
		_, _ = io.WriteString(w, `{"items":[`+
			`{"accountId":"300000000001","actionType":"Rightsize","currencyCode":"USD","currentResourceType":"Ec2Instance","estimatedMonthlySavings":40.5,"recommendationId":"r-1","region":"us-east-1","resourceId":"i-payer"},`+
			`{"accountId":"399999999999","actionType":"Stop","currencyCode":"USD","currentResourceType":"Ec2Instance","estimatedMonthlySavings":9,"recommendationId":"r-2","region":"us-east-1","resourceId":"i-nobody"}]}`)
	default:
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"__type":"ValidationException","message":"unexpected"}`)
	}
}

// readsSTS assumes any role, recording each AssumeRole's ExternalId and
// session policy, and hands out session credentials ASIAREADS.
type readsSTS struct {
	mu      sync.Mutex
	assumed []url.Values
}

func (s *readsSTS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	form, _ := url.ParseQuery(string(body))
	s.mu.Lock()
	s.assumed = append(s.assumed, form)
	s.mu.Unlock()
	switch form.Get("Action") {
	case "GetCallerIdentity":
		_, _ = io.WriteString(w, `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult><Arn>arn:aws:sts::200000000001:assumed-role/keel/keel</Arn><UserId>AROA:keel</UserId><Account>200000000001</Account></GetCallerIdentityResult><ResponseMetadata><RequestId>r</RequestId></ResponseMetadata></GetCallerIdentityResponse>`)
	case "AssumeRole":
		_, _ = io.WriteString(w, `<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleResult><AssumedRoleUser><Arn>arn:aws:sts::300000000001:assumed-role/KeelReadOnly/keel</Arn><AssumedRoleId>AROA:keel</AssumedRoleId></AssumedRoleUser>`+
			`<Credentials><AccessKeyId>ASIAREADS</AccessKeyId><SecretAccessKey>secret</SecretAccessKey><SessionToken>token</SessionToken><Expiration>2099-01-01T00:00:00Z</Expiration></Credentials>`+
			`</AssumeRoleResult><ResponseMetadata><RequestId>r</RequestId></ResponseMetadata></AssumeRoleResponse>`)
	default:
		w.WriteHeader(http.StatusBadRequest)
	}
}

func openKinds(t *testing.T, c clientWorld, tenant string) []string {
	t.Helper()
	var out []string
	if err := c.st.InTenant(context.Background(), tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(context.Background(), `SELECT kind || ' ' || severity || ' ' || fingerprint FROM findings WHERE status = 'open' AND kind IN ('cloud_budget', 'cloud_security', 'rightsizing') ORDER BY 1`)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, pgx.RowTo[string])
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func readsWorld(t *testing.T) (clientWorld, string) {
	t.Helper()
	c := newClientWorld(t, "aws")
	var externalID string
	if err := c.st.InTenant(context.Background(), c.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT role_external_id FROM client_payers WHERE cloud_account_id = $1`, c.account).Scan(&externalID)
	}); err != nil {
		t.Fatal(err)
	}
	return c, externalID
}

var emptyBucket = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
	_, _ = io.WriteString(w, `<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>b</Name><KeyCount>0</KeyCount><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated></ListBucketResult>`)
})

// TestAWSClientReadsThroughTheReadOnlyRole: after the bill sync, the
// production client reads assume the payer's role from Keel's identity with
// the payer's ExternalId and a session policy allowing only the three read
// actions, call only DescribeBudgets, GetFindings and ListRecommendations
// with that session, and land the payer's own budget, finding and
// recommendation in its Tenant. The unregistered account's finding and
// recommendation go nowhere, not even to the home Tenant.
func TestAWSClientReadsThroughTheReadOnlyRole(t *testing.T) {
	c, externalID := readsWorld(t)
	ctx := context.Background()
	sts, api := &readsSTS{}, &fakeAWSAPI{}
	stsSrv, apiSrv, s3 := httptest.NewServer(sts), httptest.NewServer(api), httptest.NewServer(emptyBucket)
	defer stsSrv.Close()
	defer apiSrv.Close()
	defer s3.Close()

	syncClients(ctx, []*cost.ClientBillSync{awsClientBillSync(&cost.Ingester{Store: c.st}, webIdentity{}, stsSrv.URL, s3.URL)},
		map[string]*clientreads.Sync{"aws": awsClientReads(c.st, webIdentity{}, stsSrv.URL, apiSrv.URL)})

	want := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["budgets:ViewBudget","securityhub:GetFindings","cost-optimization-hub:ListRecommendations"],"Resource":"*"}]}`
	var readsSessions int
	for _, a := range sts.assumed {
		if a.Get("Action") != "AssumeRole" || a.Get("Policy") != want {
			continue
		}
		readsSessions++
		if a.Get("RoleArn") != "arn:aws:iam::300000000001:role/KeelReadOnly" || a.Get("ExternalId") != externalID {
			t.Errorf("reads assumed %s with ExternalId %q, want the payer's role with %q", a.Get("RoleArn"), a.Get("ExternalId"), externalID)
		}
	}
	if readsSessions != 1 {
		t.Fatalf("STS calls %v, want one AssumeRole with the reads session policy", sts.assumed)
	}
	ops := slices.Clone(api.ops)
	slices.Sort(ops)
	if want := []string{"AWSBudgetServiceGateway.DescribeBudgets", "CostOptimizationHubService.ListRecommendations", "POST /findings"}; !slices.Equal(ops, want) {
		t.Errorf("AWS calls %v, want only the three reads %v", ops, want)
	}
	for _, s := range api.signers {
		if !strings.Contains(s, "Credential=ASIAREADS/") {
			t.Errorf("AWS read signed by %q, want the client role's session", s)
		}
	}
	got := openKinds(t, c, c.tenant)
	wantOpen := []string{
		"cloud_budget high cloud_budget:aws/300000000001/org-monthly",
		"cloud_security critical cloud_security:aws/300000000001/arn:aws:securityhub:us-east-1:300000000001:finding/f-1",
	}
	if len(got) != 3 || !slices.Equal(got[:2], wantOpen) || !strings.HasPrefix(got[2], "rightsizing ") {
		t.Errorf("client Tenant Findings %v, want %v and one rightsizing Finding", got, wantOpen)
	}
	if got := openKinds(t, c, c.home); len(got) != 0 {
		t.Errorf("home Tenant Findings %v, want none from a client's cloud", got)
	}
}

// TestClientReadsWaitForKeelsIdentity: when STS rejects Keel's own
// identity, the bill sync stops before any client role and so do the
// reads: no AssumeRole, no read call, nothing in the client's Tenant.
func TestClientReadsWaitForKeelsIdentity(t *testing.T) {
	c, _ := readsWorld(t)
	ctx := context.Background()
	fake := &fakeSTS{provider: "aws"}
	fake.set(false, true)
	api := &fakeAWSAPI{}
	stsSrv, apiSrv := httptest.NewServer(fake), httptest.NewServer(api)
	defer stsSrv.Close()
	defer apiSrv.Close()

	syncClients(ctx, []*cost.ClientBillSync{awsClientBillSync(&cost.Ingester{Store: c.st}, webIdentity{}, stsSrv.URL, "")},
		map[string]*clientreads.Sync{"aws": awsClientReads(c.st, webIdentity{}, stsSrv.URL, apiSrv.URL)})

	if got := fake.calls(); !slices.Equal(got, []string{"GetCallerIdentity"}) {
		t.Errorf("STS calls %v, want only Keel's own identity check", got)
	}
	if len(api.ops) != 0 {
		t.Errorf("AWS calls %v with Keel's identity rejected", api.ops)
	}
	if got := openKinds(t, c, c.tenant); len(got) != 0 {
		t.Errorf("client Tenant Findings %v, want none", got)
	}
}
