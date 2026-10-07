package breakglass_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/breakglass"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

type audit struct{ events []breakglass.Event }

func (a audit) Events(context.Context, string, time.Time) ([]breakglass.Event, error) {
	return a.events, nil
}

func TestBreakGlassUseNeedsPostMortemAndDrillsComeDue(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	home, _ := s.CreateTenant(ctx, "harmonyx", "HarmonyX", true)
	admin := activity.Actor{Type: activity.ActorHuman, UID: "user:admin@harmonyx.co"}
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	log := &audit{}
	svc := breakglass.Service{Store: s, Now: func() time.Time { return now }, Audit: func(string) (breakglass.Audit, error) { return log, nil }}
	if _, err := svc.Register(ctx, breakglass.Identity{Account: "200045645249", PrincipalID: "100099", Name: "breakglass-1", Holder: "CTO safe"}, admin); !errors.Is(err, breakglass.ErrInvalid) {
		t.Fatalf("no hardware MFA accepted: %v", err)
	}
	id, err := svc.Register(ctx, breakglass.Identity{Account: "200045645249", PrincipalID: "100099", Name: "breakglass-1", Holder: "CTO safe", HardwareMFA: true}, admin)
	if err != nil {
		t.Fatal(err)
	}
	if names, _ := svc.Names(ctx, "", "200045645249"); !names["breakglass-1"] {
		t.Fatal("names for standing access")
	}
	if res, _ := svc.Watch(ctx, time.Hour); res.Uses != 0 || res.DrillsOverdue != 0 {
		t.Fatalf("quiet %+v", res)
	}
	log.events = []breakglass.Event{{ID: "ev-1", Name: "ConsoleLogin", SourceIP: "203.0.113.9", At: now.Add(-10 * time.Minute)}}
	if res, _ := svc.Watch(ctx, time.Hour); res.Uses != 1 {
		t.Fatalf("use not detected %+v", res)
	}
	if res, _ := svc.Watch(ctx, time.Hour); res.Uses != 0 {
		t.Fatal("same event counted twice")
	}
	var useID, sev string
	if err := s.InTenant(ctx, home, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT id::text FROM breakglass_uses`).Scan(&useID); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT severity FROM findings WHERE kind = 'breakglass' AND status = 'open'`).Scan(&sev)
	}); err != nil || sev != "critical" {
		t.Fatalf("finding %s %v", sev, err)
	}
	if err := svc.PostMortem(ctx, useID, "http://wiki/pm", admin); !errors.Is(err, breakglass.ErrInvalid) {
		t.Fatalf("non-https post-mortem: %v", err)
	}
	if err := svc.PostMortem(ctx, useID, "https://wiki.harmonyx.co/pm/2026-10-07", admin); err != nil {
		t.Fatal(err)
	}
	// 91 days on, the drill is overdue until one is recorded.
	now = now.Add(91 * 24 * time.Hour)
	log.events = nil
	if res, _ := svc.Watch(ctx, time.Hour); res.DrillsOverdue != 1 {
		t.Fatalf("drill %+v", res)
	}
	if err := svc.Drill(ctx, id.ID, "logged in with the YubiKey, listed members, logged out", admin); err != nil {
		t.Fatal(err)
	}
	var open int
	if err := s.InTenant(ctx, home, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM findings WHERE kind = 'breakglass' AND status = 'open'`).Scan(&open)
	}); err != nil || open != 0 {
		t.Fatalf("open %d %v", open, err)
	}
}
