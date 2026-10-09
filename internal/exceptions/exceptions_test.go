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
	svc := exceptions.New(s) // wall clock: River fires the expiry timer on wall time
	c, _ := flowtest.Client(t, s, svc.Register)
	svc.SetClient(c)

	excepted := func() bool {
		var b bool
		if err := s.InTenant(ctx, tenant, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT finding_excepted(f, $2) FROM findings f WHERE id = $1`, finding, svc.Now()).Scan(&b)
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

func TestRevokeKeepsApprovalTime(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "tat", "TAT", false)
	svc := exceptions.New(s)
	svc.Now = storetest.Clock()
	c, _ := flowtest.Client(t, s, svc.Register)
	svc.SetClient(c)
	e, err := svc.Create(ctx, tenant, exceptions.Request{Fingerprint: "vuln:CVE-2026-2:", Reason: "base image patch lands next sprint", ExpiresAt: svc.Now().Add(time.Hour)}, eng)
	if err != nil {
		t.Fatal(err)
	}
	if left := e.ExpiresAt.Sub(e.CreatedAt); left <= 0 || left > time.Hour {
		t.Fatalf("requested for an hour, recorded as lasting %v from its request", left)
	}
	approved, err := svc.Approve(ctx, tenant, e.ID, "accepted risk", sec)
	if err != nil {
		t.Fatal(err)
	}
	if approved.ApprovedAt == nil || approved.RevokedAt != nil {
		t.Fatalf("approved: approved_at %v revoked_at %v", approved.ApprovedAt, approved.RevokedAt)
	}
	if left := approved.ExpiresAt.Sub(*approved.ApprovedAt); left <= 0 || left > time.Hour {
		t.Fatalf("approved %v before an expiry an hour away", left)
	}
	revoked, err := svc.Revoke(ctx, tenant, e.ID, "patched early", sec)
	if err != nil {
		t.Fatal(err)
	}
	if revoked.RevokedAt == nil || revoked.RevokedAt.Before(*approved.ApprovedAt) || !revoked.RevokedAt.Before(revoked.ExpiresAt) {
		t.Fatalf("revoked at %v, outside approval %v to expiry %v", revoked.RevokedAt, approved.ApprovedAt, revoked.ExpiresAt)
	}
	if revoked.RevokedAt == nil || !revoked.DecidedAt.Equal(*approved.DecidedAt) || !revoked.ApprovedAt.Equal(*approved.ApprovedAt) {
		t.Fatalf("revoke moved the approval: decided_at %v -> %v, approved_at %v -> %v, revoked_at %v",
			approved.DecidedAt, revoked.DecidedAt, approved.ApprovedAt, revoked.ApprovedAt, revoked.RevokedAt)
	}
}

func TestRejectStampsDecisionOnServiceClock(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "tdc", "TDC", false)
	svc := exceptions.New(s)
	svc.Now = storetest.Clock()
	c, _ := flowtest.Client(t, s, svc.Register)
	svc.SetClient(c)
	e, err := svc.Create(ctx, tenant, exceptions.Request{Fingerprint: "vuln:CVE-2026-3:", Reason: "vendor fix is not out yet", ExpiresAt: svc.Now().Add(time.Hour)}, eng)
	if err != nil {
		t.Fatal(err)
	}
	before := svc.Now().Truncate(time.Microsecond)
	rejected, err := svc.Reject(ctx, tenant, e.ID, "not accepted", sec)
	if err != nil {
		t.Fatal(err)
	}
	after := svc.Now()
	if rejected.DecidedAt == nil || rejected.DecidedAt.Before(before) || rejected.DecidedAt.After(after) {
		t.Fatalf("rejected between %v and %v on the service clock, recorded decided_at %v", before, after, rejected.DecidedAt)
	}
}

// The gate asks at the caller's clock time: an Exception that expired on the
// service clock no longer covers its Finding, whatever the database's now().
func TestExceptedAtTheCallersTime(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	tenant, _ := s.CreateTenant(ctx, "tat", "TAT", false)
	expires := storetest.Epoch.Add(-time.Hour)
	var excepted []bool
	if err := s.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		var finding string
		if err := tx.QueryRow(ctx, `INSERT INTO findings (tenant_id, kind, fingerprint, severity, title) VALUES ($1, 'vulnerability', 'vuln:CVE-2026-2:crm-api', 'critical', 'CVE-2026-2') RETURNING id`, tenant).Scan(&finding); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO exceptions (tenant_id, finding_ids, reason, state, requested_by, expires_at) VALUES ($1, ARRAY[$2::uuid], 'patched in the next release', 'approved', 'a', $3)`, tenant, finding, expires); err != nil {
			return err
		}
		for _, at := range []time.Time{expires.Add(-time.Minute), expires.Add(time.Minute)} {
			var b bool
			if err := tx.QueryRow(ctx, `SELECT finding_excepted(f, $2) FROM findings f WHERE id = $1`, finding, at).Scan(&b); err != nil {
				return err
			}
			excepted = append(excepted, b)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !excepted[0] || excepted[1] {
		t.Fatalf("excepted a minute before and after expiry: %v, want [true false]", excepted)
	}
}
