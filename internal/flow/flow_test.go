package flow_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/flow"
	"github.com/hx-thanadej/keel/internal/store"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

type quick struct{}

func (quick) NextRetry(*rivertype.JobRow) time.Time { return time.Now().Add(10 * time.Millisecond) }

var admin = activity.Actor{Type: activity.ActorHuman, UID: "user:admin@harmonyx.co"}

// start runs a River client for e until the test ends.
func start(t *testing.T, st *store.Store, e *flow.Engine) func() {
	t.Helper()
	w := river.NewWorkers()
	e.Register(w)
	c, err := flow.NewClient(st.AppPool(), w, flow.ClientOptions{RetryPolicy: quick{}, PollInterval: 20 * time.Millisecond, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	e.SetClient(c)
	ctx, cancel := context.WithCancel(context.Background())
	if err := c.Start(ctx); err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	stop := func() {
		once.Do(func() {
			sc, done := context.WithTimeout(context.Background(), 5*time.Second)
			defer done()
			_ = c.Stop(sc)
			cancel()
		})
	}
	t.Cleanup(stop)
	return stop
}

func wait(t *testing.T, e *flow.Engine, tenant, id string, states ...string) flow.Flow {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		f, err := e.Get(context.Background(), tenant, id)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range states {
			if f.State == s {
				return f
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("flow stuck in %s: %+v", f.State, f.Steps)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

type counters struct{ a, b, c, undoA, undoB atomic.Int32 }

func def(n *counters, failB func() error) flow.Def {
	return flow.Def{Kind: "demo", Steps: []flow.Step{
		{Name: "a", Do: func(_ context.Context, r *flow.Run) (map[string]any, error) {
			n.a.Add(1)
			return map[string]any{"account": "uin-" + r.Str("name")}, nil
		}, Undo: func(context.Context, *flow.Run) error { n.undoA.Add(1); return nil }},
		{Name: "b", MaxAttempts: 3, Do: func(_ context.Context, r *flow.Run) (map[string]any, error) {
			n.b.Add(1)
			if err := failB(); err != nil {
				return nil, err
			}
			return map[string]any{"seen": r.Out("a", "account")}, nil
		}, Undo: func(context.Context, *flow.Run) error { n.undoB.Add(1); return nil }},
		{Name: "c", Do: func(context.Context, *flow.Run) (map[string]any, error) { n.c.Add(1); return nil, nil }},
	}}
}

func tenant(t *testing.T, st *store.Store) string {
	id, err := st.CreateTenant(context.Background(), "tat", "TAT", false)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestFlowRunsStepsInOrderPassingOutputs(t *testing.T) {
	st := storetest.New(t)
	ten := tenant(t, st)
	n := &counters{}
	e := flow.New(st, def(n, func() error { return nil }))
	start(t, st, e)
	f, created, err := e.Start(context.Background(), ten, "demo", "environment/1", map[string]any{"name": "dev"}, admin)
	if err != nil || !created {
		t.Fatal(err, created)
	}
	// Asking again returns the same run.
	again, created, err := e.Start(context.Background(), ten, "demo", "environment/1", nil, admin)
	if err != nil || created || again.ID != f.ID {
		t.Fatalf("second start %v %v %v", again.ID, created, err)
	}
	f = wait(t, e, ten, f.ID, "succeeded")
	if f.Steps[1].Output["seen"] != "uin-dev" || n.a.Load() != 1 || n.b.Load() != 1 || n.c.Load() != 1 {
		t.Fatalf("steps %+v counts %d %d %d", f.Steps, n.a.Load(), n.b.Load(), n.c.Load())
	}
	var types []string
	if err := st.InTenant(context.Background(), ten, func(tx pgx.Tx) error {
		rows, err := tx.Query(context.Background(), `SELECT type FROM activities WHERE subject = $1 ORDER BY seq`, "flow/"+f.ID)
		if err != nil {
			return err
		}
		types, err = pgx.CollectRows(rows, pgx.RowTo[string])
		return err
	}); err != nil {
		t.Fatal(err)
	}
	want := []string{"keel.flow.started", "keel.flow.step.succeeded", "keel.flow.step.succeeded", "keel.flow.step.succeeded", "keel.flow.succeeded"}
	if len(types) != len(want) {
		t.Fatalf("activities %v", types)
	}
	for i := range want {
		if types[i] != want[i] {
			t.Fatalf("activities %v", types)
		}
	}
}

func TestFlowSurvivesRestart(t *testing.T) {
	st := storetest.New(t)
	ten := tenant(t, st)
	n := &counters{}
	e := flow.New(st, def(n, func() error { return nil }))
	stop := start(t, st, e)
	stop() // the process "dies" before any work happens
	f, _, err := e.Start(context.Background(), ten, "demo", "environment/2", nil, admin)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if n.a.Load() != 0 {
		t.Fatal("ran without a client")
	}
	e2 := flow.New(st, def(n, func() error { return nil }))
	start(t, st, e2) // a new process picks the job up
	wait(t, e2, ten, f.ID, "succeeded")
}

func TestFailedFlowRetriesFromTheFailedStep(t *testing.T) {
	st := storetest.New(t)
	ten := tenant(t, st)
	n := &counters{}
	var broken atomic.Bool
	broken.Store(true)
	e := flow.New(st, def(n, func() error {
		if broken.Load() {
			return errors.New("member account quota reached")
		}
		return nil
	}))
	start(t, st, e)
	f, _, err := e.Start(context.Background(), ten, "demo", "environment/3", nil, admin)
	if err != nil {
		t.Fatal(err)
	}
	f = wait(t, e, ten, f.ID, "failed")
	if n.b.Load() != 3 || f.Steps[1].State != "failed" || f.Error == nil || *f.Error != "b: member account quota reached" {
		t.Fatalf("after failure: b ran %d, %+v", n.b.Load(), f)
	}
	broken.Store(false)
	if err := e.Retry(context.Background(), ten, f.ID, admin); err != nil {
		t.Fatal(err)
	}
	wait(t, e, ten, f.ID, "succeeded")
	if n.a.Load() != 1 {
		t.Fatalf("step a re-ran: %d", n.a.Load())
	}
	if err := e.Retry(context.Background(), ten, f.ID, admin); !errors.Is(err, flow.ErrState) {
		t.Fatalf("retry of succeeded flow: %v", err)
	}
}

func TestPermanentErrorFailsAtOnceAndCancelUndoes(t *testing.T) {
	st := storetest.New(t)
	ten := tenant(t, st)
	n := &counters{}
	e := flow.New(st, def(n, func() error { return flow.Permanent(errors.New("name already taken")) }))
	start(t, st, e)
	f, _, err := e.Start(context.Background(), ten, "demo", "environment/4", nil, admin)
	if err != nil {
		t.Fatal(err)
	}
	wait(t, e, ten, f.ID, "failed")
	if n.b.Load() != 1 {
		t.Fatalf("permanent error retried: %d", n.b.Load())
	}
	if err := e.Cancel(context.Background(), ten, f.ID, "", admin); !errors.Is(err, flow.ErrState) {
		t.Fatalf("cancel without reason: %v", err)
	}
	if err := e.Cancel(context.Background(), ten, f.ID, "wrong project name", admin); err != nil {
		t.Fatal(err)
	}
	f = wait(t, e, ten, f.ID, "cancelled")
	if n.undoA.Load() != 1 || n.undoB.Load() != 0 || f.Steps[0].State != "compensated" || f.Steps[1].State != "failed" {
		t.Fatalf("undo a=%d b=%d steps %+v", n.undoA.Load(), n.undoB.Load(), f.Steps)
	}
	// A cancelled flow no longer blocks a fresh start.
	g, created, err := e.Start(context.Background(), ten, "demo", "environment/4", nil, admin)
	if err != nil || !created || g.ID == f.ID {
		t.Fatalf("restart after cancel %v %v", created, err)
	}
}
