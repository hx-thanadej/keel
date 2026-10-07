package activity_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/store"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

func sample(tenant string) activity.Activity {
	return activity.Activity{
		TenantID:  tenant,
		Source:    "keel/catalog",
		Type:      "keel.project.created",
		Subject:   "project/tat-crm",
		Operation: "CreateProject",
		Kind:      activity.Create,
		Actor:     activity.Actor{Type: activity.ActorHuman, UID: "user:thanadej"},
		Resources: []activity.Resource{{Type: "project", UID: "p1"}},
		Why:       activity.Why{Reason: "new client engagement"},
		Outcome:   activity.Success,
	}
}

func TestEnvelopeIsCloudEventWithOCSFAPIActivity(t *testing.T) {
	a := sample("7b0f9c1e-0000-4000-8000-000000000001")
	a.Time = time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC)
	raw, err := activity.Envelope("01-id", a)
	if err != nil {
		t.Fatal(err)
	}
	var ev struct {
		SpecVersion string `json:"specversion"`
		ID          string `json:"id"`
		Source      string `json:"source"`
		Type        string `json:"type"`
		Subject     string `json:"subject"`
		Time        string `json:"time"`
		Data        struct {
			ClassUID    int    `json:"class_uid"`
			CategoryUID int    `json:"category_uid"`
			ActivityID  int    `json:"activity_id"`
			TypeUID     int    `json:"type_uid"`
			StatusID    int    `json:"status_id"`
			TimeMs      int64  `json:"time"`
			TenantID    string `json:"tenant_id"`
			API         struct {
				Operation string `json:"operation"`
			} `json:"api"`
			Actor struct {
				Type string `json:"type"`
				UID  string `json:"uid"`
			} `json:"actor"`
			Why struct {
				Reason string `json:"reason"`
			} `json:"why"`
			Metadata struct {
				Version string `json:"version"`
			} `json:"metadata"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &ev); err != nil {
		t.Fatal(err)
	}
	if ev.SpecVersion != "1.0" || ev.ID != "01-id" || ev.Source != "keel/catalog" || ev.Type != "keel.project.created" || ev.Subject != "project/tat-crm" {
		t.Errorf("cloudevent attrs wrong: %+v", ev)
	}
	if ev.Time != "2026-10-07T09:00:00Z" {
		t.Errorf("time = %q", ev.Time)
	}
	d := ev.Data
	if d.ClassUID != 6003 || d.CategoryUID != 6 || d.ActivityID != 1 || d.TypeUID != 600301 || d.StatusID != 1 {
		t.Errorf("ocsf ids wrong: %+v", d)
	}
	if d.TimeMs != a.Time.UnixMilli() || d.TenantID != a.TenantID || d.API.Operation != "CreateProject" || d.Actor.UID != "user:thanadej" || d.Why.Reason != "new client engagement" || d.Metadata.Version == "" {
		t.Errorf("ocsf fields wrong: %+v", d)
	}
}

func TestValidate(t *testing.T) {
	cases := map[string]func(*activity.Activity){
		"no tenant":    func(a *activity.Activity) { a.TenantID = "" },
		"no type":      func(a *activity.Activity) { a.Type = "" },
		"no source":    func(a *activity.Activity) { a.Source = "" },
		"no actor":     func(a *activity.Activity) { a.Actor = activity.Actor{} },
		"bad actor":    func(a *activity.Activity) { a.Actor.Type = "robot" },
		"no operation": func(a *activity.Activity) { a.Operation = "" },
		"no outcome":   func(a *activity.Activity) { a.Outcome = 0 },
		"no kind":      func(a *activity.Activity) { a.Kind = 0 },
	}
	for name, mutate := range cases {
		a := sample("7b0f9c1e-0000-4000-8000-000000000001")
		mutate(&a)
		if err := a.Validate(); err == nil {
			t.Errorf("%s: want validation error", name)
		}
	}
	if err := sample("x").Validate(); err != nil {
		t.Errorf("valid sample: %v", err)
	}
}

func record(t *testing.T, s *store.Store, a activity.Activity) string {
	t.Helper()
	var id string
	err := s.InTenant(context.Background(), a.TenantID, func(tx pgx.Tx) error {
		var err error
		id, err = activity.Record(context.Background(), tx, a)
		return err
	})
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	return id
}

func TestRecordAndListAreTenantScoped(t *testing.T) {
	s := storetest.New(t)
	ctx := context.Background()
	a, _ := s.CreateTenant(ctx, "tat", "TAT", false)
	b, _ := s.CreateTenant(ctx, "acme", "Acme", false)

	idA := record(t, s, sample(a))
	record(t, s, sample(b))

	var got []activity.Stored
	err := s.InTenant(ctx, a, func(tx pgx.Tx) error {
		var err error
		got, err = activity.List(ctx, tx, activity.Filter{Limit: 50})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != idA {
		t.Fatalf("tenant A sees %d activities (%v), want only its own", len(got), got)
	}
	if got[0].Seq <= 0 || got[0].LoggedAt.IsZero() || len(got[0].Event) == 0 {
		t.Errorf("stored activity missing seq/logged_at/event: %+v", got[0])
	}
}

func TestRecordRejectsOtherTenantsActivity(t *testing.T) {
	s := storetest.New(t)
	ctx := context.Background()
	a, _ := s.CreateTenant(ctx, "tat", "TAT", false)
	b, _ := s.CreateTenant(ctx, "acme", "Acme", false)

	err := s.InTenant(ctx, a, func(tx pgx.Tx) error {
		_, err := activity.Record(ctx, tx, sample(b))
		return err
	})
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
		t.Fatalf("err = %v, want RLS violation", err)
	}
}

func TestActivitiesAreAppendOnly(t *testing.T) {
	s := storetest.New(t)
	ctx := context.Background()
	a, _ := s.CreateTenant(ctx, "tat", "TAT", false)
	id := record(t, s, sample(a))

	for _, stmt := range []string{
		`UPDATE activities SET type = 'tampered' WHERE id = $1`,
		`DELETE FROM activities WHERE id = $1`,
	} {
		err := s.InTenant(ctx, a, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, stmt, id)
			return err
		})
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
			t.Errorf("%q: err = %v, want insufficient_privilege", stmt, err)
		}
	}
	err := s.InTenant(ctx, a, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `TRUNCATE activities`)
		return err
	})
	if err == nil {
		t.Error("TRUNCATE succeeded, want denied")
	}
}

func TestListFilters(t *testing.T) {
	s := storetest.New(t)
	ctx := context.Background()
	a, _ := s.CreateTenant(ctx, "tat", "TAT", false)

	one := sample(a)
	two := sample(a)
	two.Actor.UID = "pipeline:run-9"
	two.Actor.Type = activity.ActorPipeline
	two.Type = "keel.release.created"
	record(t, s, one)
	record(t, s, two)

	err := s.InTenant(ctx, a, func(tx pgx.Tx) error {
		got, err := activity.List(ctx, tx, activity.Filter{ActorUID: "pipeline:run-9", Limit: 10})
		if err != nil {
			return err
		}
		if len(got) != 1 || got[0].Type != "keel.release.created" {
			t.Errorf("actor filter returned %v", got)
		}
		got, err = activity.List(ctx, tx, activity.Filter{Type: "keel.project.created", Limit: 10})
		if err != nil {
			return err
		}
		if len(got) != 1 {
			t.Errorf("type filter returned %d", len(got))
		}
		got, err = activity.List(ctx, tx, activity.Filter{Limit: 10})
		if len(got) != 2 || got[0].Seq < got[1].Seq {
			t.Errorf("list should be newest first: %v", got)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestWriteLatency(t *testing.T) {
	if testing.Short() {
		t.Skip("latency check")
	}
	s := storetest.New(t)
	ctx := context.Background()
	a, _ := s.CreateTenant(ctx, "tat", "TAT", false)

	const n = 200
	var worst time.Duration
	for i := 0; i < n; i++ {
		start := time.Now()
		record(t, s, sample(a))
		if d := time.Since(start); d > worst {
			worst = d
		}
	}
	if worst > time.Second {
		t.Fatalf("worst write latency %v over %d writes, want ≤ 1s", worst, n)
	}
}
