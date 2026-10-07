package exceptions_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/exceptions"
	"github.com/hx-thanadej/keel/internal/flow/flowtest"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

var (
	eng = activity.Actor{Type: activity.ActorHuman, UID: "user:eng@harmonyx.co"}
	sec = activity.Actor{Type: activity.ActorHuman, UID: "user:security@harmonyx.co"}
)

func TestExceptionLifecycleWithDurableExpiry(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "tat", "TAT", false)
	var finding string
	if err := s.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `INSERT INTO findings (tenant_id, kind, fingerprint, severity, title) VALUES ($1, 'vulnerability', 'vuln:CVE-2026-1:crm-api', 'critical', 'CVE-2026-1') RETURNING id`, tenant).Scan(&finding)
	}); err != nil {
		t.Fatal(err)
	}
	svc := exceptions.New(s)
	c, _ := flowtest.Client(t, s, svc.Register)
	svc.SetClient(c)

	excepted := func() bool {
		var b bool
		if err := s.InTenant(ctx, tenant, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT finding_excepted(f) FROM findings f WHERE id = $1`, finding).Scan(&b)
		}); err != nil {
			t.Fatal(err)
		}
		return b
	}
	if _, err := svc.Create(ctx, tenant, exceptions.Request{FindingIDs: []string{finding}, Reason: "short", ExpiresAt: time.Now().Add(time.Hour)}, eng); !errors.Is(err, exceptions.ErrInvalid) {
		t.Fatalf("short reason: %v", err)
	}
	if _, err := svc.Create(ctx, tenant, exceptions.Request{FindingIDs: []string{finding}, Reason: "base image patch lands next sprint", ExpiresAt: time.Now().Add(100 * 24 * time.Hour)}, eng); !errors.Is(err, exceptions.ErrInvalid) {
		t.Fatalf("over 90 days: %v", err)
	}
	e, err := svc.Create(ctx, tenant, exceptions.Request{Fingerprint: "vuln:CVE-2026-1:", Reason: "base image patch lands next sprint", ExpiresAt: time.Now().Add(3 * time.Second)}, eng)
	if err != nil {
		t.Fatal(err)
	}
	if excepted() {
		t.Fatal("excepted before approval")
	}
	if _, err := svc.Approve(ctx, tenant, e.ID, "", eng); !errors.Is(err, exceptions.ErrState) {
		t.Fatalf("self-approval: %v", err)
	}
	if _, err := svc.Approve(ctx, tenant, e.ID, "accepted risk: not internet-facing", sec); err != nil {
		t.Fatal(err)
	}
	if !excepted() {
		t.Fatal("not excepted after approval")
	}
	// The River timer expires it; the Finding counts again and says why.
	deadline := time.Now().Add(20 * time.Second)
	for excepted() {
		if time.Now().After(deadline) {
			t.Fatal("exception never expired")
		}
		time.Sleep(200 * time.Millisecond)
	}
	var state, lapsed string
	if err := s.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		for time.Now().Before(deadline) {
			if err := tx.QueryRow(ctx, `SELECT e.state, coalesce(f.detail->>'exception_lapsed', '') FROM exceptions e, findings f WHERE e.id = $1 AND f.id = $2`, e.ID, finding).Scan(&state, &lapsed); err != nil {
				return err
			}
			if state == "expired" {
				return nil
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if state != "expired" || lapsed != e.ID {
		t.Fatalf("state %s lapsed %q", state, lapsed)
	}
	if _, err := svc.Approve(ctx, tenant, e.ID, "", sec); !errors.Is(err, exceptions.ErrState) {
		t.Fatalf("re-approve expired: %v", err)
	}
}
