package reports

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"
)

type runArgs struct{}

func (runArgs) Kind() string { return "keel_reports_run" }

type runWorker struct {
	river.WorkerDefaults[runArgs]
	s Service
}

func (w *runWorker) Work(ctx context.Context, _ *river.Job[runArgs]) error {
	n, err := w.s.Run(ctx)
	if n > 0 {
		slog.Info("monthly reports", "generated", n)
	}
	return err
}

// Register adds the worker that runs monthly report generation.
func (s Service) Register(w *river.Workers) { river.AddWorker(w, &runWorker{s: s}) }

// SetClient schedules Run hourly on c, and once at start, so a new month's
// reports appear early on the first. Only the elected River leader enqueues
// it, so replicas do not race each other.
func (s Service) SetClient(c *river.Client[pgx.Tx]) {
	c.PeriodicJobs().Add(river.NewPeriodicJob(river.PeriodicInterval(time.Hour),
		func() (river.JobArgs, *river.InsertOpts) { return runArgs{}, &river.InsertOpts{MaxAttempts: 3} },
		&river.PeriodicJobOpts{ID: runArgs{}.Kind(), RunOnStart: true}))
}
