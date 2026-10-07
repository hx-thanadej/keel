package landingzone_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/flow"
	"github.com/hx-thanadej/keel/internal/flow/flowtest"
	"github.com/hx-thanadej/keel/internal/landingzone"
	"github.com/hx-thanadej/keel/internal/vending"
)

type oneAccount struct{}

func (oneAccount) Provider() string                                          { return "tencent" }
func (oneAccount) EnsureUnit(context.Context, string) (string, error)        { return "5", nil }
func (oneAccount) FindAccount(context.Context, string) (string, bool, error) { return "", false, nil }
func (oneAccount) CreateAccount(context.Context, string, string, map[string]string) (string, error) {
	return "300001", nil
}
func (oneAccount) AccountReady(context.Context, string) (bool, error) { return true, nil }

func TestVendedAccountGetsTheBaseline(t *testing.T) {
	w := setup(t)
	ctx := context.Background()
	var dev, project string
	if err := w.s.InTenant(ctx, w.tenant, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT project_id::text FROM environments WHERE id = $1`, w.env).Scan(&project); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `INSERT INTO environments (tenant_id, project_id, name) VALUES ($1, $2, 'dev') RETURNING id`, w.tenant, project).Scan(&dev)
	}); err != nil {
		t.Fatal(err)
	}
	org := newOrg()
	v := vending.Vendor{Store: w.s, Org: oneAccount{}, Baseline: []flow.Step{landingzone.Step(w.s, org, base)}}
	e := flow.New(w.s, v.Def())
	flowtest.Start(t, w.s, e)
	f, _, err := v.Request(ctx, e, w.tenant, project, dev, activity.Actor{Type: activity.ActorHuman, UID: "user:a"})
	if err != nil {
		t.Fatal(err)
	}
	f = flowtest.Wait(t, e, w.tenant, f.ID, "succeeded")
	if f.Steps[len(f.Steps)-1].Output["version"] != "keel-baseline@1" || len(org.attached["300001"]) != 3 {
		t.Fatalf("step %+v attached %v", f.Steps[len(f.Steps)-1], org.attached)
	}
	var version string
	if err := w.s.InTenant(ctx, w.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT baseline_version FROM cloud_accounts WHERE external_id = '300001'`).Scan(&version)
	}); err != nil || version != "keel-baseline@1" {
		t.Fatalf("version %q %v", version, err)
	}
}
