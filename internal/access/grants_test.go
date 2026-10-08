package access_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/access"
	"github.com/hx-thanadej/keel/internal/auth"
	"github.com/hx-thanadej/keel/internal/flow/flowtest"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

func person(email, tenant, team string, roles ...string) auth.Principal {
	p := auth.Principal{Subject: "user:" + email, Kind: auth.KindHuman, TenantID: "home", Home: true}
	for _, r := range roles {
		b := auth.Binding{Role: r, TenantID: tenant}
		if team != "" {
			b.TeamIDs = []string{team}
		}
		p.Bindings = append(p.Bindings, b)
	}
	return p
}

func grantState(t *testing.T, w world, id string) string {
	var s string
	if err := w.s.InTenant(context.Background(), w.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT state FROM access_grants WHERE id = $1`, id).Scan(&s)
	}); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestAccessGrantLifecycle(t *testing.T) {
	w := setup(t)
	ctx := context.Background()
	dir := newDir()
	svc, err := access.New(w.s, dir)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := flowtest.Client(t, w.s, svc.Register)
	svc.SetClient(c)
	eng := person("eng@harmonyx.co", w.tenant, w.team, "engineer")
	leadP := person("lead@harmonyx.co", w.tenant, w.team, "team_lead")
	secP := person("security@harmonyx.co", w.tenant, "", "security_lead")
	outsider := person("other@harmonyx.co", w.tenant, "00000000-0000-4000-8000-000000000000", "engineer")

	devRO, _ := svc.RequestRole(ctx, w.tenant, w.dev, w.team, "read-only", lead)
	prodOp, _ := svc.RequestRole(ctx, w.tenant, w.prod, w.team, "operator", lead)
	if prodOp, err = svc.DecideRole(ctx, w.tenant, prodOp.ID, true, sec); err != nil {
		t.Fatal(err)
	}

	// Read-only outside production: active at once, expires on its own.
	svc.Now = func() time.Time { return time.Now().Add(-time.Hour + 2*time.Second) } // a 1h grant that ends in ~2s
	g, err := svc.RequestGrant(ctx, w.tenant, devRO.ID, 1, "look at failing pods", eng)
	if err != nil || g.State != "active" || !dir.assignments["rc-keel-read-only|100001|u-eng"] {
		t.Fatalf("auto grant %+v %v %v", g, err, dir.assignments)
	}
	deadline := time.Now().Add(20 * time.Second)
	for grantState(t, w, g.ID) != "expired" {
		if time.Now().After(deadline) {
			t.Fatal("grant never expired")
		}
		time.Sleep(200 * time.Millisecond)
	}
	if dir.assignments["rc-keel-read-only|100001|u-eng"] {
		t.Fatal("assignment outlived the grant")
	}
	svc.Now = storetest.Clock()

	// Not a member of the Team / too long: denied with reasons, nothing assigned.
	if d, _ := svc.RequestGrant(ctx, w.tenant, devRO.ID, 1, "curious about things", outsider); d.State != "denied" || !strings.Contains(strings.Join(d.Decision.Reasons, ";"), "only members") {
		t.Fatalf("outsider %+v", d)
	}
	if d, _ := svc.RequestGrant(ctx, w.tenant, prodOp.ID, 6, "incident 4711 recovery", eng); d.State != "denied" || !strings.Contains(d.Decision.Reasons[0], "at most 2 hours") {
		t.Fatalf("too long %+v", d)
	}

	// Write in production: Team Lead and Security Lead, two different people.
	g, err = svc.RequestGrant(ctx, w.tenant, prodOp.ID, 2, "incident 4711 recovery", eng)
	if err != nil || g.State != "requested" || strings.Join(g.Decision.Approvals, "+") != "team_lead+security_lead" {
		t.Fatalf("prod write %+v %v", g, err)
	}
	if _, err := svc.Approve(ctx, w.tenant, g.ID, eng); !errors.Is(err, access.ErrState) {
		t.Fatalf("self approval: %v", err)
	}
	if g, err = svc.Approve(ctx, w.tenant, g.ID, leadP); err != nil || g.State != "requested" || len(g.Approvals) != 1 {
		t.Fatalf("first approval %+v %v", g, err)
	}
	if _, err := svc.Approve(ctx, w.tenant, g.ID, leadP); !errors.Is(err, access.ErrState) {
		t.Fatalf("second approval by the same person: %v", err)
	}
	if g, err = svc.Approve(ctx, w.tenant, g.ID, secP); err != nil || g.State != "active" || !dir.assignments["rc-keel-operator|100002|u-eng"] {
		t.Fatalf("second approval %+v %v", g, err)
	}
	if g, err = svc.Revoke(ctx, w.tenant, g.ID, "incident closed", lead); err != nil || g.State != "revoked" || dir.assignments["rc-keel-operator|100002|u-eng"] {
		t.Fatalf("revoke %+v %v", g, err)
	}
	if g.CreatedAt.After(*g.ActivatedAt) || g.EndedAt.Before(*g.ActivatedAt) {
		t.Fatalf("grant out of order: created %v, active %v, ended %v", g.CreatedAt, g.ActivatedAt, g.EndedAt)
	}
	before := svc.Now().Truncate(time.Microsecond)
	d, err := svc.RequestGrant(ctx, w.tenant, prodOp.ID, 2, "incident 4712 recovery", eng)
	if err != nil {
		t.Fatal(err)
	}
	if after := svc.Now(); d.CreatedAt.Before(before) || d.CreatedAt.After(after) {
		t.Fatalf("grant requested between %v and %v on the service clock, recorded created_at %v", before, after, d.CreatedAt)
	}
	if d, err = svc.Reject(ctx, w.tenant, d.ID, "use the runbook", leadP); err != nil || d.EndedAt.Before(d.CreatedAt) {
		t.Fatalf("rejected grant ended %v before its request %v (%v)", d.EndedAt, d.CreatedAt, err)
	}
}
