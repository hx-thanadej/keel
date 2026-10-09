package access_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/access"
	"github.com/hx-thanadej/keel/internal/flow/flowtest"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

type users []string

func (u users) Users(context.Context) ([]string, error) { return u, nil }

func TestStandingAccessReport(t *testing.T) {
	w := setup(t)
	ctx := context.Background()
	dir := newDir()
	svc, _ := access.New(w.s, dir)
	c, _ := flowtest.Client(t, w.s, svc.Register)
	svc.SetClient(c)
	ro, _ := svc.RequestRole(ctx, w.tenant, w.prod, w.team, "read-only", lead)
	eng := person("eng@harmonyx.co", w.tenant, w.team, "engineer")
	leadP := person("lead@harmonyx.co", w.tenant, w.team, "team_lead")
	g, _ := svc.RequestGrant(ctx, w.tenant, ro.ID, 1, "check prod dashboards", eng)
	if g, _ = svc.Approve(ctx, w.tenant, g.ID, leadP); g.State != "active" {
		t.Fatalf("grant %+v", g)
	}
	// Someone assigned an admin role configuration by hand, and a CAM user exists.
	dir.assignments["rc-console-admin|100002|u-mallory"] = true
	camUsers := users{"breakglass-1", "alice"}
	s := access.Standing{Store: w.s, Directory: dir, Users: func(string) (access.Users, error) { return camUsers, nil },
		BreakGlass: func(context.Context, string, string) (map[string]bool, error) {
			return map[string]bool{"breakglass-1": true}, nil
		}, Now: storetest.Clock()}
	res, err := s.Run(ctx)
	if err != nil || res.Accounts != 1 || res.Standing != 2 || res.Excused != 2 {
		t.Fatalf("%+v %v", res, err)
	}
	var titles []string
	if err := w.s.InTenant(ctx, w.tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT title FROM findings WHERE kind = 'standing_access' AND status = 'open' AND severity = 'critical' ORDER BY title`)
		if err != nil {
			return err
		}
		titles, err = pgx.CollectRows(rows, pgx.RowTo[string])
		return err
	}); err != nil || len(titles) != 2 {
		t.Fatalf("%v %v", titles, err)
	}
	delete(dir.assignments, "rc-console-admin|100002|u-mallory")
	camUsers = users{"breakglass-1"}
	if res, _ := s.Run(ctx); res.Standing != 0 {
		t.Fatalf("after cleanup %+v", res)
	}
	storetest.ClockedFindings(t, w.s, "standing_access")
}
