package tencent_test

import (
	"context"
	"testing"

	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	org "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/organization/v20210331"

	"github.com/hx-thanadej/keel/internal/cloud/tencent"
	"github.com/hx-thanadej/keel/internal/landingzone"
)

type fakePolicyAPI struct {
	docs     map[uint64]string
	names    map[uint64]string
	attached map[uint64][]uint64
	updates  int
	creates  int
}

func (f *fakePolicyAPI) ListPoliciesWithContext(_ context.Context, r *org.ListPoliciesRequest) (*org.ListPoliciesResponse, error) {
	res := org.NewListPoliciesResponse()
	res.Response = &org.ListPoliciesResponseParams{}
	for id, n := range f.names {
		if *r.Scope != "Local" {
			panic("must search only custom policies")
		}
		res.Response.List = append(res.Response.List, &org.ListPolicyNode{PolicyId: common.Uint64Ptr(id), PolicyName: common.StringPtr(n)})
	}
	return res, nil
}
func (f *fakePolicyAPI) CreatePolicyWithContext(_ context.Context, r *org.CreatePolicyRequest) (*org.CreatePolicyResponse, error) {
	f.creates++
	id := uint64(500 + len(f.names))
	f.names[id], f.docs[id] = *r.Name, *r.Content
	res := org.NewCreatePolicyResponse()
	res.Response = &org.CreatePolicyResponseParams{PolicyId: common.Uint64Ptr(id)}
	return res, nil
}
func (f *fakePolicyAPI) UpdatePolicyWithContext(_ context.Context, r *org.UpdatePolicyRequest) (*org.UpdatePolicyResponse, error) {
	f.updates++
	f.docs[uint64(*r.PolicyId)] = *r.Content
	res := org.NewUpdatePolicyResponse()
	res.Response = &org.UpdatePolicyResponseParams{}
	return res, nil
}
func (f *fakePolicyAPI) DescribePolicyWithContext(_ context.Context, r *org.DescribePolicyRequest) (*org.DescribePolicyResponse, error) {
	res := org.NewDescribePolicyResponse()
	res.Response = &org.DescribePolicyResponseParams{PolicyDocument: common.StringPtr(f.docs[*r.PolicyId])}
	return res, nil
}
func (f *fakePolicyAPI) ListPoliciesForTargetWithContext(_ context.Context, r *org.ListPoliciesForTargetRequest) (*org.ListPoliciesForTargetResponse, error) {
	res := org.NewListPoliciesForTargetResponse()
	res.Response = &org.ListPoliciesForTargetResponseParams{}
	for _, id := range f.attached[*r.TargetId] {
		res.Response.List = append(res.Response.List, &org.ListPoliciesForTarget{StrategyId: common.Uint64Ptr(id)})
	}
	return res, nil
}
func (f *fakePolicyAPI) AttachPolicyWithContext(_ context.Context, r *org.AttachPolicyRequest) (*org.AttachPolicyResponse, error) {
	if *r.TargetType != "MEMBER" {
		panic("attach to members")
	}
	f.attached[*r.TargetId] = append(f.attached[*r.TargetId], *r.PolicyId)
	res := org.NewAttachPolicyResponse()
	res.Response = &org.AttachPolicyResponseParams{}
	return res, nil
}

func TestGuardrailsApplyAndDrift(t *testing.T) {
	ctx := context.Background()
	f := &fakePolicyAPI{docs: map[uint64]string{}, names: map[uint64]string{}, attached: map[uint64][]uint64{}}
	g := tencent.Guardrails{API: f}
	b := landingzone.Tencent(landingzone.Options{AutomationRole: "keel-automation"})
	if err := landingzone.Apply(ctx, g, b, "100001"); err != nil {
		t.Fatal(err)
	}
	if f.creates != 3 || len(f.attached[100001]) != 3 {
		t.Fatalf("creates %d attached %v", f.creates, f.attached)
	}
	// Tencent may return the document re-formatted; that is not drift.
	for id, d := range f.docs {
		f.docs[id] = " " + d + "\n"
	}
	if d, err := landingzone.Check(ctx, g, b, "100001"); err != nil || len(d) != 0 {
		t.Fatalf("formatting counted as drift: %v %v", d, err)
	}
	// A loosened policy is drift, and Apply puts it back via UpdatePolicy.
	for id, n := range f.names {
		if n == "keel_protect_audit" {
			f.docs[id] = `{"version":"2.0","statement":[]}`
		}
	}
	if d, _ := landingzone.Check(ctx, g, b, "100001"); len(d) != 1 || d[0].Problem != "content_changed" {
		t.Fatalf("drift %v", d)
	}
	if err := landingzone.Apply(ctx, g, b, "100001"); err != nil || f.updates != 1 || f.creates != 3 {
		t.Fatalf("re-apply: %v updates %d creates %d", err, f.updates, f.creates)
	}
	if _, err := g.Attached(ctx, "not-a-uin", "SERVICE_CONTROL_POLICY"); err == nil {
		t.Fatal("bad uin accepted")
	}
}
