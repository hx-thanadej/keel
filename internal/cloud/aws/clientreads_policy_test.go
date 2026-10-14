package aws

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	sdk "github.com/aws/aws-sdk-go-v2/aws"
	coh "github.com/aws/aws-sdk-go-v2/service/costoptimizationhub"
)

// TestReadsPolicyScopesWhatAWSLetsItScope: budgets and Security Hub take
// the payer's own budget and hub ARNs; Cost Optimization Hub and
// aws-portal define no resource types, so only they keep "*".
func TestReadsPolicyScopesWhatAWSLetsItScope(t *testing.T) {
	for name, tc := range map[string]struct{ arn, region, want string }{
		"aws": {"arn:aws:iam::300000000001:role/KeelReadOnly", "ap-southeast-1", `{"Version":"2012-10-17","Statement":[` +
			`{"Effect":"Allow","Action":"budgets:ViewBudget","Resource":"arn:aws:budgets::300000000001:budget/*"},` +
			`{"Effect":"Allow","Action":"aws-portal:ViewBilling","Resource":"*"},` +
			`{"Effect":"Allow","Action":"securityhub:GetFindings","Resource":"arn:aws:securityhub:ap-southeast-1:300000000001:hub/default"},` +
			`{"Effect":"Allow","Action":"cost-optimization-hub:ListRecommendations","Resource":"*"}]}`},
		"govcloud": {"arn:aws-us-gov:iam::300000000001:role/KeelReadOnly", "us-gov-west-1", `{"Version":"2012-10-17","Statement":[` +
			`{"Effect":"Allow","Action":"budgets:ViewBudget","Resource":"arn:aws-us-gov:budgets::300000000001:budget/*"},` +
			`{"Effect":"Allow","Action":"aws-portal:ViewBilling","Resource":"*"},` +
			`{"Effect":"Allow","Action":"securityhub:GetFindings","Resource":"arn:aws-us-gov:securityhub:us-gov-west-1:300000000001:hub/default"},` +
			`{"Effect":"Allow","Action":"cost-optimization-hub:ListRecommendations","Resource":"*"}]}`},
	} {
		m, err := clientRoleARN(tc.arn, "300000000001", "ext")
		if err != nil {
			t.Fatal(err)
		}
		got, err := readsPolicy(m[1], m[2], tc.region)
		if err != nil || got != tc.want {
			t.Errorf("%s: policy %s, %v\nwant %s", name, got, err, tc.want)
		}
	}
	for _, region := range []string{"", "*", "us-east-1:*", "${aws:RequestedRegion}"} {
		if got, err := readsPolicy("aws", "300000000001", region); err == nil {
			t.Errorf("region %q: policy %s, want refused", region, got)
		}
	}
}

// TestCOHListIsAllPagesOrNothing: a listing whose second page fails
// returns no recommendations, only the error, so no caller can mistake a
// partial listing for a complete one.
func TestCOHListIsAllPagesOrNothing(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if calls.Add(1) == 1 {
			if strings.Contains(string(body), "nextToken") {
				t.Errorf("first page asked with a token: %s", body)
			}
			_, _ = io.WriteString(w, `{"items":[{"accountId":"300000000001","actionType":"Rightsize","currencyCode":"USD","estimatedMonthlySavings":5,"resourceId":"i-1"}],"nextToken":"p2"}`)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"__type":"ThrottlingException","message":"slow down"}`)
	}))
	defer srv.Close()
	c := &COH{client: coh.New(coh.Options{Region: "us-east-1", Credentials: sdk.AnonymousCredentials{}, BaseEndpoint: sdk.String(srv.URL),
		RetryMaxAttempts: 1})}
	recs, err := c.List(context.Background())
	if err == nil || recs != nil {
		t.Fatalf("List = %v, %v; want no recommendations and the page error", recs, err)
	}
	if calls.Load() != 2 {
		t.Errorf("%d calls, want both pages asked", calls.Load())
	}
}
