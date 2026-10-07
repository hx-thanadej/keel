package flow

import (
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
)

// ClientOptions tunes the River client; zero values are production defaults.
type ClientOptions struct {
	Workers      int                     // concurrent jobs, default 10
	RetryPolicy  river.ClientRetryPolicy // default: River's exponential backoff
	PollInterval time.Duration           // default 1s
	Logger       *slog.Logger
}

// NewClient builds Keel's River client on the application pool. Jobs only
// carry a Tenant id and a row id; their work runs under RLS like any request.
func NewClient(pool *pgxpool.Pool, workers *river.Workers, o ClientOptions) (*river.Client[pgx.Tx], error) {
	if o.Workers == 0 {
		o.Workers = 10
	}
	return river.NewClient(riverpgxv5.New(pool), &river.Config{
		Queues:            map[string]river.QueueConfig{river.QueueDefault: {MaxWorkers: o.Workers}},
		Workers:           workers,
		RetryPolicy:       o.RetryPolicy,
		FetchPollInterval: o.PollInterval,
		FetchCooldown:     min(o.PollInterval, 100*time.Millisecond),
		Logger:            o.Logger,
	})
}
