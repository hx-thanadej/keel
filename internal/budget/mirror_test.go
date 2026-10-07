package budget_test

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/budget"
)

// fakeNative is an in-memory provider budget service.
type fakeNative struct {
	mu   sync.Mutex
	next int
	m    map[string]budget.NativeSpec
	ops  []string
}

func newFake() *fakeNative { return &fakeNative{m: map[string]budget.NativeSpec{}} }

func (f *fakeNative) Provider() string { return "tencent" }
func (f *fakeNative) Create(_ context.Context, s budget.NativeSpec) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.next++
	id := fmt.Sprintf("nb-%d", f.next)
	f.m[id] = s
	f.ops = append(f.ops, "create")
	return id, nil
}
func (f *fakeNative) Update(_ context.Context, id string, s budget.NativeSpec) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.m[id] = s
	f.ops = append(f.ops, "update")
	return nil
}
func (f *fakeNative) Get(_ context.Context, id string) (budget.NativeSpec, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.m[id]
	return s, ok, nil
}
func (f *fakeNative) Delete(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.m, id)
	f.ops = append(f.ops, "delete")
	return nil
}

func TestMirrorCreateDriftAndArchive(t *testing.T) {
	w := setup(t) // TAT in THB; prod + dev Tencent accounts; FX 1 USD = 35 THB
	ctx := context.Background()
	svc := budget.Service{Store: w.s}
	b, err := svc.Create(ctx, w.tat, budget.Budget{ProjectID: w.project, Name: "tat-crm 2026", Year: 2026, Amount: "365000", MirrorNative: true,
		Thresholds: []budget.Threshold{{Pct: 80, Basis: "actual"}, {Pct: 100, Basis: "forecast"}}})
	must(t, err)
	_, err = svc.Create(ctx, w.tat, budget.Budget{ProjectID: w.project, EnvironmentID: &w.prod, Name: "not mirrored", Year: 2026, Amount: "1"})
	must(t, err)

	fake := newFake()
	m := budget.Mirror{Service: svc, Natives: map[string]budget.Native{"tencent": fake}, BillingCurrency: map[string]string{"tencent": "USD"},
		Now: func() time.Time { return time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC) }}
	rep, err := m.SyncAll(ctx)
	must(t, err)
	if rep.Created != 1 || len(fake.m) != 1 {
		t.Fatalf("report %+v, natives %d", rep, len(fake.m))
	}
	var spec budget.NativeSpec
	for _, s := range fake.m {
		spec = s
	}
	// Project-level budget covers both Environments' Tencent accounts; 30000 THB in Sep = 857.14 USD.
	if strings.Join(spec.Accounts, ",") != "200046202634,200048351622" || spec.Monthly[8] != "857.14" || spec.Currency != "USD" || spec.Basis != "effective" || len(spec.Thresholds) != 2 || spec.Year != 2026 {
		t.Fatalf("spec %+v", spec)
	}

	// Idempotent.
	rep, err = m.SyncAll(ctx)
	must(t, err)
	if rep.Created+rep.Updated+rep.Recreated != 0 {
		t.Fatalf("second sync changed things: %+v", rep)
	}

	// Someone edits it in the provider console: drift corrected and recorded.
	for id, s := range fake.m {
		s.Monthly[8] = "1.00"
		fake.m[id] = s
	}
	rep, err = m.SyncAll(ctx)
	must(t, err)
	if rep.Updated != 1 || len(rep.Drift) != 1 || !strings.Contains(rep.Drift[0], "monthly amounts") {
		t.Fatalf("drift report %+v", rep)
	}
	// Someone deletes it: recreated.
	for id := range fake.m {
		delete(fake.m, id)
	}
	rep, err = m.SyncAll(ctx)
	must(t, err)
	if rep.Recreated != 1 || len(fake.m) != 1 {
		t.Fatalf("recreate report %+v", rep)
	}

	var acts int
	must(t, w.s.InTenant(ctx, w.tat, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM activities WHERE type LIKE 'keel.budget.mirror%'`).Scan(&acts)
	}))
	if acts != 3 { // created, drift corrected, recreated
		t.Errorf("mirror activities = %d, want 3", acts)
	}

	// Archiving the Keel budget removes its native mirror.
	must(t, svc.Archive(ctx, w.tat, b.ID))
	rep, err = m.SyncAll(ctx)
	must(t, err)
	if rep.Deleted != 1 || len(fake.m) != 0 {
		t.Fatalf("archive report %+v natives %d", rep, len(fake.m))
	}
}

func TestMirrorSkipsWhenNoAccountsOrNoFX(t *testing.T) {
	w := setup(t)
	ctx := context.Background()
	svc := budget.Service{Store: w.s}
	_, err := svc.Create(ctx, w.tat, budget.Budget{ProjectID: w.project, Provider: ptr("aws"), Name: "aws only", Year: 2026, Amount: "1000", MirrorNative: true})
	must(t, err)
	fake := newFake()
	m := budget.Mirror{Service: svc, Natives: map[string]budget.Native{"tencent": fake}, BillingCurrency: map[string]string{"tencent": "USD"},
		Now: func() time.Time { return time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC) }}
	rep, err := m.SyncAll(ctx)
	must(t, err)
	if rep.Created != 0 || len(fake.m) != 0 {
		t.Fatalf("aws-only budget mirrored to tencent: %+v", rep)
	}
}
