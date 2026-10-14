package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/catalog"
	"github.com/hx-thanadej/keel/internal/cost"
	"github.com/hx-thanadej/keel/internal/rightsize"
	"github.com/hx-thanadej/keel/internal/utilisation"
)

// assumeRecorder is an STS that records every AssumeRole target and refuses
// it, so no job goes on to call a real Tencent endpoint.
type assumeRecorder struct {
	mu      sync.Mutex
	targets []string
}

func (a *assumeRecorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var body struct{ RoleArn string }
	raw, _ := io.ReadAll(r.Body)
	_ = json.Unmarshal(raw, &body)
	a.mu.Lock()
	a.targets = append(a.targets, r.Header.Get("X-TC-Action")+" "+body.RoleArn)
	a.mu.Unlock()
	_, _ = io.WriteString(w, `{"Response":{"Error":{"Code":"InvalidParameter.RoleNotExist","Message":"test"},"RequestId":"r"}}`)
}

func (a *assumeRecorder) take() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := slices.Clone(a.targets)
	slices.Sort(out)
	a.targets = nil
	return slices.Compact(out)
}

const platformAccount = "200000000021"

// TestKeelsMemberRoleSkipsClientAccounts: the waste scan and the
// utilisation job, wired as in production, assume Keel's member role in the
// home Tenant's platform-owned account and never in a client-owned one
// (ADR-0018), although the client's payer and member account both carry
// CVM costs (#240).
func TestKeelsMemberRoleSkipsClientAccounts(t *testing.T) {
	c, _ := tencentReadsWorld(t)
	ctx := context.Background()
	if err := c.st.InTenant(ctx, c.home, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO cloud_accounts (tenant_id, provider, external_id, name) VALUES ($1, 'tencent', $2, 'platform')`, c.home, platformAccount)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	today := time.Now().UTC().Truncate(24 * time.Hour)
	period := time.Date(today.Year(), today.Month(), 1, 0, 0, 0, 0, time.UTC)
	day := today.AddDate(0, 0, -1)
	line := cost.Line{SubAccountID: platformAccount, BillingPeriodStart: period, ChargePeriodStart: day, ChargePeriodEnd: day.AddDate(0, 0, 1),
		ChargeCategory: "Usage", BilledCost: "2.00", BillingCurrency: "USD", ServiceName: "Cloud Virtual Machine", ResourceID: "ins-platform", Tags: map[string]string{}, Vendor: map[string]string{}}
	if _, err := (&cost.Ingester{Store: c.st}).Load(ctx, cost.Load{Provider: "tencent", BillingAccountID: "200000000001", BillingPeriod: period, Lines: []cost.Line{line}}); err != nil {
		t.Fatal(err)
	}

	sts := &assumeRecorder{}
	srv := httptest.NewServer(sts)
	defer srv.Close()
	base := staticCreds{id: "base-id"}
	want := []string{"AssumeRole qcs::cam::uin/" + platformAccount + ":roleName/KeelMember"}

	waste := rightsize.WasteEngine{Service: rightsize.Service{Store: c.st}, GraceDays: 7,
		Scanner: tencentWasteScanner(c.st, base, "KeelMember", "ap-bangkok", srv.URL)}
	res, err := waste.Run(ctx)
	if err != nil {
		t.Fatalf("waste scan: %v", err)
	}
	if got := sts.take(); !slices.Equal(got, want) {
		t.Errorf("waste scan assumed %v, want only %v", got, want)
	}
	if got := strings.Join(res.Errors, "; "); !strings.Contains(got, platformAccount) || strings.Contains(got, "30000000") {
		t.Errorf("waste scan errors %q: want only the platform account's refused AssumeRole, no attempt in a client account", got)
	}

	job := utilisation.Job{Store: utilisation.Store{Store: c.st}, CVM: tencentCVMUtilisation(c.st, base, "KeelMember", "ap-bangkok", srv.URL)}
	err = job.Run(ctx, day)
	if got := sts.take(); !slices.Equal(got, want) {
		t.Errorf("utilisation job assumed %v, want only %v", got, want)
	}
	if err == nil || !strings.Contains(err.Error(), platformAccount) || strings.Contains(err.Error(), "30000000") {
		t.Errorf("utilisation job error %v: want only the platform account's refused AssumeRole, no attempt in a client account", err)
	}
}

// TestKeelRoleRefusesClientOwnedAccounts: Keel's own role, whatever job
// builds it, makes no STS call for a client-owned Cloud Account, including
// one switched to client-owned after the role was built; Keel's payer,
// which no Tenant registers, is still reached.
func TestKeelRoleRefusesClientOwnedAccounts(t *testing.T) {
	c := newClientWorld(t, "tencent")
	ctx := context.Background()
	sts := &assumeRecorder{}
	srv := httptest.NewServer(sts)
	defer srv.Close()
	base := staticCreds{id: "base-id"}
	if _, err := keelRole(c.st, base, c.payer, "KeelMember", "ap-bangkok", srv.URL); !errors.Is(err, catalog.ErrClientOwned) {
		t.Errorf("Keel's role in client-owned %s: %v, want ErrClientOwned", c.payer, err)
	}
	r, err := keelRole(c.st, base, "200045645249", "KeelMember", "ap-bangkok", srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.GetCredential(); errors.Is(err, catalog.ErrClientOwned) {
		t.Errorf("Keel's payer refused: %v", err)
	}
	if got, want := sts.take(), []string{"AssumeRole qcs::cam::uin/200045645249:roleName/KeelMember"}; !slices.Equal(got, want) {
		t.Errorf("STS saw %v, want only %v", got, want)
	}

	switched, err := keelRole(c.st, base, platformAccount, "KeelMember", "ap-bangkok", srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.st.InTenant(ctx, c.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO cloud_accounts (tenant_id, provider, external_id, name, ownership, read_only_role)
			VALUES ($1, 'tencent', $2, 'now the client''s', 'client', jsonb_build_object('role_arn', 'qcs::cam::uin/'||$2||':roleName/R'))`, c.tenant, platformAccount)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := switched.GetCredential(); !errors.Is(err, catalog.ErrClientOwned) {
		t.Errorf("Keel's role built before %s became client-owned: %v, want ErrClientOwned", platformAccount, err)
	}
	if got := sts.take(); len(got) != 0 {
		t.Errorf("STS saw %v, want nothing", got)
	}
}
