package tencent_test

import (
	"context"
	"testing"

	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	tcr "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/tcr/v20190924"

	"github.com/hx-thanadej/keel/internal/cloud/tencent"
)

type fakeTCR struct {
	ns        []*tcr.TcrNamespaceInfo
	created   *tcr.CreateNamespaceRequest
	rules     []*tcr.ImmutableTagRule
	retention []*tcr.RetentionPolicy
	keep      int64
}

func (f *fakeTCR) DescribeNamespacesWithContext(context.Context, *tcr.DescribeNamespacesRequest) (*tcr.DescribeNamespacesResponse, error) {
	r := tcr.NewDescribeNamespacesResponse()
	r.Response = &tcr.DescribeNamespacesResponseParams{NamespaceList: f.ns}
	return r, nil
}
func (f *fakeTCR) CreateNamespaceWithContext(_ context.Context, q *tcr.CreateNamespaceRequest) (*tcr.CreateNamespaceResponse, error) {
	f.created = q
	f.ns = append(f.ns, &tcr.TcrNamespaceInfo{Name: q.NamespaceName, NamespaceId: common.Int64Ptr(31)})
	return tcr.NewCreateNamespaceResponse(), nil
}
func (f *fakeTCR) DescribeImmutableTagRulesWithContext(context.Context, *tcr.DescribeImmutableTagRulesRequest) (*tcr.DescribeImmutableTagRulesResponse, error) {
	r := tcr.NewDescribeImmutableTagRulesResponse()
	r.Response = &tcr.DescribeImmutableTagRulesResponseParams{Rules: f.rules}
	return r, nil
}
func (f *fakeTCR) CreateImmutableTagRulesWithContext(_ context.Context, q *tcr.CreateImmutableTagRulesRequest) (*tcr.CreateImmutableTagRulesResponse, error) {
	rule := *q.Rule
	rule.NsName = q.NamespaceName
	f.rules = append(f.rules, &rule)
	return tcr.NewCreateImmutableTagRulesResponse(), nil
}
func (f *fakeTCR) DescribeTagRetentionRulesWithContext(context.Context, *tcr.DescribeTagRetentionRulesRequest) (*tcr.DescribeTagRetentionRulesResponse, error) {
	r := tcr.NewDescribeTagRetentionRulesResponse()
	r.Response = &tcr.DescribeTagRetentionRulesResponseParams{RetentionPolicyList: f.retention}
	return r, nil
}
func (f *fakeTCR) CreateTagRetentionRuleWithContext(_ context.Context, q *tcr.CreateTagRetentionRuleRequest) (*tcr.CreateTagRetentionRuleResponse, error) {
	f.keep = *q.RetentionRule.Value
	n := "tat-tat-crm"
	f.retention = append(f.retention, &tcr.RetentionPolicy{NamespaceName: &n})
	return tcr.NewCreateTagRetentionRuleResponse(), nil
}

func TestTCRRegistryIsIdempotent(t *testing.T) {
	f := &fakeTCR{}
	r := tencent.Registry{API: f, RegistryID: "tcr-abc"}
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		id, created, err := r.EnsureNamespace(ctx, "tat-tat-crm")
		if err != nil || id != 31 || created != (i == 0) {
			t.Fatalf("pass %d: %d %v %v", i, id, created, err)
		}
		if c, err := r.EnsureImmutableTags(ctx, "tat-tat-crm"); err != nil || c != (i == 0) {
			t.Fatalf("immutable pass %d: %v %v", i, c, err)
		}
		if c, err := r.EnsureRetention(ctx, "tat-tat-crm", id, 30); err != nil || c != (i == 0) {
			t.Fatalf("retention pass %d: %v %v", i, c, err)
		}
	}
	if *f.created.IsPublic || !*f.created.IsAutoScan || f.keep != 30 || len(f.rules) != 1 {
		t.Fatalf("%+v keep %d rules %d", f.created, f.keep, len(f.rules))
	}
}
