// Package flow runs durable multi-step work (#87, ADR-0014): account vending,
// repository creation, promotions. A flow is a row per run plus a row per
// step; each step is an idempotent Go function driven by a River job that is
// enqueued in the same transaction as the state change causing it, so a
// restart resumes at the step that was in progress.
//
// A step that keeps failing stops the flow in state "failed". An operator
// then retries it (from the failed step) or cancels it, which runs the Undo
// of every completed step in reverse.
package flow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/store"
)

var (
	ErrNotFound = errors.New("flow not found")
	ErrState    = errors.New("flow is not in a state that allows this")
	ErrUnknown  = errors.New("unknown flow kind")
)

// Run is what a step sees.
type Run struct {
	ID, Tenant, Kind, Subject string
	Input                     map[string]any
	// Outputs of the steps completed so far, by step name.
	Outputs map[string]map[string]any
	Attempt int
}

// Str returns a string from the input, or "" if absent.
func (r *Run) Str(key string) string {
	s, _ := r.Input[key].(string)
	return s
}

// Out returns a value a previous step produced.
func (r *Run) Out(step, key string) string {
	s, _ := r.Outputs[step][key].(string)
	return s
}

// Step is one unit of work. Do must be idempotent: after a crash it may run
// again for the same flow. Undo reverses it when the flow is cancelled.
type Step struct {
	Name        string
	Do          func(ctx context.Context, r *Run) (map[string]any, error)
	Undo        func(ctx context.Context, r *Run) error
	MaxAttempts int // default 8
}

// Def is a kind of flow.
type Def struct {
	Kind  string
	Steps []Step
}

type permanent struct{ error }

func (p permanent) Unwrap() error { return p.error }

// Permanent marks an error that retrying cannot fix; the flow fails at once.
func Permanent(err error) error { return permanent{err} }

// StepView is a step's state.
type StepView struct {
	Seq        int            `json:"seq"`
	Name       string         `json:"name"`
	State      string         `json:"state"`
	Attempts   int            `json:"attempts"`
	Output     map[string]any `json:"output"`
	Error      *string        `json:"error"`
	StartedAt  *time.Time     `json:"started_at"`
	FinishedAt *time.Time     `json:"finished_at"`
}

// Flow is a run and its steps.
type Flow struct {
	ID         string         `json:"id"`
	Kind       string         `json:"kind"`
	Subject    string         `json:"subject"`
	Input      map[string]any `json:"input"`
	State      string         `json:"state"`
	Error      *string        `json:"error"`
	CreatedBy  string         `json:"created_by"`
	CreatedAt  time.Time      `json:"created_at"`
	UpdatedAt  time.Time      `json:"updated_at"`
	FinishedAt *time.Time     `json:"finished_at"`
	Steps      []StepView     `json:"steps,omitempty"`
}

// Engine starts and drives flows.
type Engine struct {
	Store  *store.Store
	defs   map[string]Def
	client *river.Client[pgx.Tx]
}

// New registers flow kinds.
func New(st *store.Store, defs ...Def) *Engine {
	e := &Engine{Store: st, defs: map[string]Def{}}
	for _, d := range defs {
		e.defs[d.Kind] = d
	}
	return e
}

// Register adds the engine's workers to a River worker set.
func (e *Engine) Register(w *river.Workers) {
	river.AddWorker(w, &stepWorker{e: e})
	river.AddWorker(w, &compensateWorker{e: e})
}

// SetClient gives the engine the River client used to enqueue jobs.
func (e *Engine) SetClient(c *river.Client[pgx.Tx]) { e.client = c }

type stepArgs struct {
	Tenant string `json:"tenant"`
	FlowID string `json:"flow_id"`
	Seq    int    `json:"seq"`
}

func (stepArgs) Kind() string { return "keel_flow_step" }

type compensateArgs struct {
	Tenant string `json:"tenant"`
	FlowID string `json:"flow_id"`
}

func (compensateArgs) Kind() string { return "keel_flow_compensate" }

var keelActor = activity.Actor{Type: activity.ActorKeel, UID: "keel:flow"}

func (e *Engine) enqueueStep(ctx context.Context, tx pgx.Tx, tenant, id string, seq int, def Def) error {
	if e.client == nil {
		return errors.New("flow engine has no River client")
	}
	max := def.Steps[seq].MaxAttempts
	if max == 0 {
		max = 8
	}
	_, err := e.client.InsertTx(ctx, tx, stepArgs{Tenant: tenant, FlowID: id, Seq: seq}, &river.InsertOpts{MaxAttempts: max})
	return err
}

// Start begins a flow, or returns the unfinished one for the same kind and
// subject (created=false), so asking twice never does the work twice.
func (e *Engine) Start(ctx context.Context, tenant, kind, subject string, input map[string]any, by activity.Actor) (Flow, bool, error) {
	def, ok := e.defs[kind]
	if !ok {
		return Flow{}, false, fmt.Errorf("%w: %s", ErrUnknown, kind)
	}
	var id string
	created := false
	err := e.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT id::text FROM flows WHERE kind = $1 AND subject = $2 AND state IN ('running', 'failed', 'cancelling')`, kind, subject).Scan(&id)
		if err == nil {
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		in, _ := json.Marshal(nonNil(input))
		if err := tx.QueryRow(ctx, `INSERT INTO flows (tenant_id, kind, subject, input, created_by) VALUES ($1, $2, $3, $4, $5) RETURNING id::text`,
			tenant, kind, subject, in, by.UID).Scan(&id); err != nil {
			return err
		}
		for i, s := range def.Steps {
			if _, err := tx.Exec(ctx, `INSERT INTO flow_steps (tenant_id, flow_id, seq, name) VALUES ($1, $2, $3, $4)`, tenant, id, i, s.Name); err != nil {
				return err
			}
		}
		created = true
		if err := record(ctx, tx, tenant, id, "keel.flow.started", "StartFlow", activity.Create, activity.Success, by, kind+" "+subject); err != nil {
			return err
		}
		return e.enqueueStep(ctx, tx, tenant, id, 0, def)
	})
	if err != nil {
		return Flow{}, false, err
	}
	f, err := e.Get(ctx, tenant, id)
	return f, created, err
}

// Retry resumes a failed flow at its failed step.
func (e *Engine) Retry(ctx context.Context, tenant, id string, by activity.Actor) error {
	return e.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		var kind string
		var seq int
		err := tx.QueryRow(ctx, `SELECT f.kind, s.seq FROM flows f JOIN flow_steps s ON s.flow_id = f.id AND s.state = 'failed'
			WHERE f.id = $1 AND f.state = 'failed' FOR UPDATE OF f`, id).Scan(&kind, &seq)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrState
		}
		if err != nil {
			return err
		}
		def, ok := e.defs[kind]
		if !ok {
			return fmt.Errorf("%w: %s", ErrUnknown, kind)
		}
		if _, err := tx.Exec(ctx, `UPDATE flows SET state = 'running', error = NULL, updated_at = now() WHERE id = $1`, id); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE flow_steps SET state = 'pending', error = NULL WHERE flow_id = $1 AND seq = $2`, id, seq); err != nil {
			return err
		}
		if err := record(ctx, tx, tenant, id, "keel.flow.retried", "RetryFlow", activity.Update, activity.Success, by, fmt.Sprintf("from step %s", def.Steps[seq].Name)); err != nil {
			return err
		}
		return e.enqueueStep(ctx, tx, tenant, id, seq, def)
	})
}

// Cancel stops a running or failed flow and undoes its completed steps.
func (e *Engine) Cancel(ctx context.Context, tenant, id, reason string, by activity.Actor) error {
	if reason == "" {
		return fmt.Errorf("%w: a reason is required", ErrState)
	}
	return e.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE flows SET state = 'cancelling', updated_at = now() WHERE id = $1 AND state IN ('running', 'failed')`, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrState
		}
		if err := record(ctx, tx, tenant, id, "keel.flow.cancel_requested", "CancelFlow", activity.Update, activity.Success, by, reason); err != nil {
			return err
		}
		if e.client == nil {
			return errors.New("flow engine has no River client")
		}
		_, err = e.client.InsertTx(ctx, tx, compensateArgs{Tenant: tenant, FlowID: id}, &river.InsertOpts{MaxAttempts: 25})
		return err
	})
}

const flowCols = `id::text, kind, subject, input, state, error, created_by, created_at, updated_at, finished_at`

func scanFlow(r pgx.Row) (Flow, error) {
	var f Flow
	var in []byte
	err := r.Scan(&f.ID, &f.Kind, &f.Subject, &in, &f.State, &f.Error, &f.CreatedBy, &f.CreatedAt, &f.UpdatedAt, &f.FinishedAt)
	if err == nil {
		_ = json.Unmarshal(in, &f.Input)
	}
	return f, err
}

// Get reads a flow with its steps.
func (e *Engine) Get(ctx context.Context, tenant, id string) (Flow, error) {
	var f Flow
	err := e.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		var err error
		f, err = scanFlow(tx.QueryRow(ctx, `SELECT `+flowCols+` FROM flows WHERE id = $1`, id))
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		f.Steps, err = steps(ctx, tx, id)
		return err
	})
	return f, err
}

// List returns recent flows, optionally of one kind or subject.
func (e *Engine) List(ctx context.Context, tenant, kind, subject string) ([]Flow, error) {
	var out []Flow
	err := e.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+flowCols+` FROM flows WHERE ($1 = '' OR kind = $1) AND ($2 = '' OR subject = $2) ORDER BY created_at DESC LIMIT 200`, kind, subject)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (Flow, error) { return scanFlow(r) })
		return err
	})
	return out, err
}

func steps(ctx context.Context, tx pgx.Tx, id string) ([]StepView, error) {
	rows, err := tx.Query(ctx, `SELECT seq, name, state, attempts, output, error, started_at, finished_at FROM flow_steps WHERE flow_id = $1 ORDER BY seq`, id)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (StepView, error) {
		var s StepView
		var out []byte
		err := r.Scan(&s.Seq, &s.Name, &s.State, &s.Attempts, &out, &s.Error, &s.StartedAt, &s.FinishedAt)
		if err == nil {
			_ = json.Unmarshal(out, &s.Output)
		}
		return s, err
	})
}

func (e *Engine) load(ctx context.Context, tx pgx.Tx, tenant, id string) (Flow, *Run, Def, error) {
	f, err := scanFlow(tx.QueryRow(ctx, `SELECT `+flowCols+` FROM flows WHERE id = $1 FOR UPDATE`, id))
	if err != nil {
		return Flow{}, nil, Def{}, err
	}
	def, ok := e.defs[f.Kind]
	if !ok {
		return Flow{}, nil, Def{}, fmt.Errorf("%w: %s", ErrUnknown, f.Kind)
	}
	if f.Steps, err = steps(ctx, tx, id); err != nil {
		return Flow{}, nil, Def{}, err
	}
	r := &Run{ID: f.ID, Tenant: tenant, Kind: f.Kind, Subject: f.Subject, Input: f.Input, Outputs: map[string]map[string]any{}}
	for _, s := range f.Steps {
		if s.State == "succeeded" {
			r.Outputs[s.Name] = s.Output
		}
	}
	return f, r, def, nil
}

type stepWorker struct {
	river.WorkerDefaults[stepArgs]
	e *Engine
}

func (w *stepWorker) Work(ctx context.Context, job *river.Job[stepArgs]) error {
	a := job.Args
	var run *Run
	var def Def
	proceed := false
	// 1. Claim the step.
	err := w.e.Store.InTenant(ctx, a.Tenant, func(tx pgx.Tx) error {
		f, r, d, err := w.e.load(ctx, tx, a.Tenant, a.FlowID)
		if err != nil {
			return err
		}
		if f.State != "running" || a.Seq >= len(f.Steps) || a.Seq >= len(d.Steps) {
			return nil // cancelled, or a duplicate job
		}
		st := f.Steps[a.Seq].State
		if st != "pending" && st != "running" {
			return nil // already done
		}
		run, def, proceed = r, d, true
		run.Attempt = job.Attempt
		_, err = tx.Exec(ctx, `UPDATE flow_steps SET state = 'running', attempts = attempts + 1, started_at = coalesce(started_at, now()) WHERE flow_id = $1 AND seq = $2`, a.FlowID, a.Seq)
		return err
	})
	if err != nil || !proceed {
		return err
	}
	step := def.Steps[a.Seq]
	// 2. Do the work outside any transaction.
	out, doErr := step.Do(ctx, run)
	// 3. Record the outcome and move on.
	final := doErr != nil && (errors.As(doErr, new(permanent)) || job.Attempt >= job.MaxAttempts)
	err = w.e.Store.InTenant(ctx, a.Tenant, func(tx pgx.Tx) error {
		var state string
		if err := tx.QueryRow(ctx, `SELECT state FROM flows WHERE id = $1 FOR UPDATE`, a.FlowID).Scan(&state); err != nil {
			return err
		}
		if doErr != nil {
			if !final {
				_, err := tx.Exec(ctx, `UPDATE flow_steps SET error = $3 WHERE flow_id = $1 AND seq = $2`, a.FlowID, a.Seq, doErr.Error())
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE flow_steps SET state = 'failed', error = $3, finished_at = now() WHERE flow_id = $1 AND seq = $2`, a.FlowID, a.Seq, doErr.Error()); err != nil {
				return err
			}
			if state == "running" {
				if _, err := tx.Exec(ctx, `UPDATE flows SET state = 'failed', error = $2, updated_at = now() WHERE id = $1`, a.FlowID, step.Name+": "+doErr.Error()); err != nil {
					return err
				}
			}
			return record(ctx, tx, a.Tenant, a.FlowID, "keel.flow.step.failed", "RunFlowStep", activity.Update, activity.Failure, keelActor, step.Name+": "+doErr.Error())
		}
		o, _ := json.Marshal(nonNil(out))
		if _, err := tx.Exec(ctx, `UPDATE flow_steps SET state = 'succeeded', output = $3, error = NULL, finished_at = now() WHERE flow_id = $1 AND seq = $2`, a.FlowID, a.Seq, o); err != nil {
			return err
		}
		if err := record(ctx, tx, a.Tenant, a.FlowID, "keel.flow.step.succeeded", "RunFlowStep", activity.Update, activity.Success, keelActor, step.Name); err != nil {
			return err
		}
		if state != "running" {
			return nil // cancelled while the step ran; compensation picks it up
		}
		if a.Seq+1 < len(def.Steps) {
			_, err := tx.Exec(ctx, `UPDATE flows SET updated_at = now() WHERE id = $1`, a.FlowID)
			if err != nil {
				return err
			}
			return w.e.enqueueStep(ctx, tx, a.Tenant, a.FlowID, a.Seq+1, def)
		}
		if _, err := tx.Exec(ctx, `UPDATE flows SET state = 'succeeded', updated_at = now(), finished_at = now() WHERE id = $1`, a.FlowID); err != nil {
			return err
		}
		return record(ctx, tx, a.Tenant, a.FlowID, "keel.flow.succeeded", "CompleteFlow", activity.Update, activity.Success, keelActor, run.Kind+" "+run.Subject)
	})
	if err != nil {
		return err
	}
	if doErr != nil && !final {
		return doErr // River retries with backoff
	}
	return nil
}

type compensateWorker struct {
	river.WorkerDefaults[compensateArgs]
	e *Engine
}

func (w *compensateWorker) Work(ctx context.Context, job *river.Job[compensateArgs]) error {
	a := job.Args
	var run *Run
	var def Def
	var done []StepView
	err := w.e.Store.InTenant(ctx, a.Tenant, func(tx pgx.Tx) error {
		f, r, d, err := w.e.load(ctx, tx, a.Tenant, a.FlowID)
		if err != nil {
			return err
		}
		if f.State != "cancelling" {
			return nil
		}
		for _, s := range f.Steps {
			if s.State == "running" {
				return river.JobSnooze(time.Second) // let the in-flight step land first
			}
		}
		run, def = r, d
		for i := len(f.Steps) - 1; i >= 0; i-- {
			if f.Steps[i].State == "succeeded" {
				done = append(done, f.Steps[i])
			}
		}
		return nil
	})
	if err != nil || run == nil {
		return err
	}
	for _, s := range done {
		if s.Seq < len(def.Steps) && def.Steps[s.Seq].Undo != nil {
			if err := def.Steps[s.Seq].Undo(ctx, run); err != nil {
				_ = w.e.Store.InTenant(ctx, a.Tenant, func(tx pgx.Tx) error {
					_, _ = tx.Exec(ctx, `UPDATE flow_steps SET error = $3 WHERE flow_id = $1 AND seq = $2`, a.FlowID, s.Seq, "undo: "+err.Error())
					return nil
				})
				return fmt.Errorf("undo %s: %w", s.Name, err)
			}
		}
		if err := w.e.Store.InTenant(ctx, a.Tenant, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `UPDATE flow_steps SET state = 'compensated', finished_at = now() WHERE flow_id = $1 AND seq = $2`, a.FlowID, s.Seq); err != nil {
				return err
			}
			return record(ctx, tx, a.Tenant, a.FlowID, "keel.flow.step.compensated", "UndoFlowStep", activity.Update, activity.Success, keelActor, s.Name)
		}); err != nil {
			return err
		}
	}
	return w.e.Store.InTenant(ctx, a.Tenant, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE flows SET state = 'cancelled', updated_at = now(), finished_at = now() WHERE id = $1 AND state = 'cancelling'`, a.FlowID); err != nil {
			return err
		}
		return record(ctx, tx, a.Tenant, a.FlowID, "keel.flow.cancelled", "CancelFlow", activity.Update, activity.Success, keelActor, run.Kind+" "+run.Subject)
	})
}

func record(ctx context.Context, tx pgx.Tx, tenant, id, typ, op string, kind activity.Kind, outcome activity.Outcome, by activity.Actor, detail string) error {
	_, err := activity.Record(ctx, tx, activity.Activity{TenantID: tenant, Source: "keel/flow", Type: typ, Subject: "flow/" + id,
		Operation: op, Kind: kind, Actor: by, Resources: []activity.Resource{{Type: "flow", UID: id}}, Outcome: outcome, StatusDetail: detail,
		Why: activity.Why{Reason: detail}})
	return err
}

func nonNil(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return m
}
