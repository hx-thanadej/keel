// Package flowtest runs a flow engine against a real River client in tests.
package flowtest

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/hx-thanadej/keel/internal/flow"
	"github.com/hx-thanadej/keel/internal/store"
)

type quick struct{}

func (quick) NextRetry(*rivertype.JobRow) time.Time { return time.Now().Add(10 * time.Millisecond) }

// Start runs a River client for e (retrying almost at once) until the test
// ends or the returned stop is called.
func Start(t *testing.T, st *store.Store, e *flow.Engine) (stop func()) {
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
	stop = func() {
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

// Wait polls until the flow reaches one of states.
func Wait(t *testing.T, e *flow.Engine, tenant, id string, states ...string) flow.Flow {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
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
			t.Fatalf("flow stuck in %s (want %v): %+v", f.State, states, f.Steps)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
