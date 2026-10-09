// Package rightsize holds Rightsizing Recommendations from every source
// (Keel's engines and provider recommenders) in one shape, and keeps each
// open one in the Findings inbox of the Project's Team (#67, ADR-0013).
package rightsize

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/store"
)

// Errors mapped by the API.
var (
	ErrNotFound = errors.New("recommendation not found")
	ErrState    = errors.New("recommendation is not in a state that allows this")
	ErrInvalid  = errors.New("invalid")
)

// Recommendation is a proposed change to a resource's size, type or existence.
type Recommendation struct {
	ID             string         `json:"id"`
	Fingerprint    string         `json:"fingerprint"`
	Source         string         `json:"source"`
	Provider       string         `json:"provider"`
	AccountID      string         `json:"account_id"`
	Region         string         `json:"region"`
	ResourceID     string         `json:"resource_id"`
	ResourceType   string         `json:"resource_type"`
	ProjectID      *string        `json:"project_id"`
	EnvironmentID  *string        `json:"environment_id"`
	Action         string         `json:"action"`
	Current        map[string]any `json:"current"`
	Recommended    map[string]any `json:"recommended"`
	Evidence       map[string]any `json:"evidence"`
	MonthlySavings string         `json:"monthly_savings"`
	Currency       string         `json:"currency"`
	SavingsBasis   string         `json:"savings_basis"`
	Confidence     float64        `json:"confidence"`
	Risk           map[string]any `json:"risk"`
	State          string         `json:"state"`
	FindingID      string         `json:"finding_id"`
	DecidedBy      *string        `json:"decided_by"`
	DecisionReason *string        `json:"decision_reason"`
	PRURL          *string        `json:"pr_url"`
	GeneratedAt    time.Time      `json:"generated_at"`
	// ObservedAt, when set by an engine, is used as generated_at for new
	// records (engines running on a backfill or test clock).
	ObservedAt time.Time `json:"-"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// Fingerprint identifies "the same advice about the same resource".
func Fingerprint(provider, resourceID, action string) string {
	return provider + "|" + resourceID + "|" + action
}

// Service stores Recommendations. Authorisation is the API's job.
type Service struct {
	Store *store.Store
	Now   func() time.Time // defaults to time.Now
}

func (s Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// materialSavingsChange re-raises dismissed advice when savings move this much.
const materialSavingsChange = 0.2

var keelActor = activity.Actor{Type: activity.ActorKeel, UID: "keel:rightsizing"}

const cols = `id::text, fingerprint, source, provider, account_id, region, resource_id, resource_type, project_id::text, environment_id::text, action,
	current, recommended, evidence, monthly_savings::text, currency, savings_basis, confidence::float8, risk, state, coalesce(finding_id::text, ''),
	decided_by, decision_reason, pr_url, generated_at, updated_at`

func scan(r pgx.Row) (Recommendation, error) {
	var x Recommendation
	var cur, rec, ev, risk []byte
	err := r.Scan(&x.ID, &x.Fingerprint, &x.Source, &x.Provider, &x.AccountID, &x.Region, &x.ResourceID, &x.ResourceType, &x.ProjectID, &x.EnvironmentID, &x.Action,
		&cur, &rec, &ev, &x.MonthlySavings, &x.Currency, &x.SavingsBasis, &x.Confidence, &risk, &x.State, &x.FindingID,
		&x.DecidedBy, &x.DecisionReason, &x.PRURL, &x.GeneratedAt, &x.UpdatedAt)
	if err == nil {
		_ = json.Unmarshal(cur, &x.Current)
		_ = json.Unmarshal(rec, &x.Recommended)
		_ = json.Unmarshal(ev, &x.Evidence)
		_ = json.Unmarshal(risk, &x.Risk)
	}
	return x, err
}

// severity from monthly savings: thresholds of 10 / 30 / 300 USD, scaled for THB.
func severity(savings, currency string) string {
	v, ok := new(big.Rat).SetString(savings)
	if !ok {
		return "low"
	}
	f, _ := v.Float64()
	if currency == "THB" {
		f /= 35
	}
	switch {
	case f >= 300:
		return "critical"
	case f >= 30:
		return "high"
	case f >= 10:
		return "medium"
	}
	return "low"
}

func material(a, b Recommendation) bool {
	if !reflect.DeepEqual(norm(a.Recommended), norm(b.Recommended)) {
		return true
	}
	x, _ := new(big.Rat).SetString(a.MonthlySavings)
	y, _ := new(big.Rat).SetString(b.MonthlySavings)
	if x == nil || y == nil || x.Sign() == 0 {
		return x == nil || y == nil || y.Sign() != 0
	}
	rel, _ := new(big.Rat).Abs(new(big.Rat).Quo(new(big.Rat).Sub(y, x), x)).Float64()
	return rel > materialSavingsChange
}

// norm round-trips through JSON so stored and fresh maps compare equal.
func norm(m map[string]any) map[string]any {
	b, _ := json.Marshal(m)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return out
}

// Upsert records the latest advice for a resource. It returns the live
// record and whether anything new was raised (false when the same advice is
// just refreshed, or when it was dismissed and nothing changed materially).
func (s Service) Upsert(ctx context.Context, tenant string, r Recommendation) (Recommendation, bool, error) {
	if r.ResourceID == "" || r.Action == "" || r.Provider == "" || r.Currency == "" {
		return Recommendation{}, false, fmt.Errorf("%w: provider, resource, action and currency are required", ErrInvalid)
	}
	if _, ok := new(big.Rat).SetString(r.MonthlySavings); !ok {
		return Recommendation{}, false, fmt.Errorf("%w: monthly_savings must be a decimal", ErrInvalid)
	}
	r.Fingerprint = Fingerprint(r.Provider, r.ResourceID, r.Action)
	if r.SavingsBasis == "" {
		r.SavingsBasis = "effective"
	}
	var out Recommendation
	changed := false
	now := s.now()
	err := s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		live, err := scan(tx.QueryRow(ctx, `SELECT `+cols+` FROM recommendations WHERE fingerprint = $1 AND state IN ('open', 'accepted')`, r.Fingerprint))
		hasLive := err == nil
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if hasLive && !material(live, r) {
			_, err := tx.Exec(ctx, `UPDATE recommendations SET monthly_savings = $2::numeric, evidence = $3, confidence = $4, updated_at = now() WHERE id = $1`,
				live.ID, r.MonthlySavings, mustJSON(r.Evidence), r.Confidence)
			out = live
			return err
		}
		if !hasLive {
			last, err := scan(tx.QueryRow(ctx, `SELECT `+cols+` FROM recommendations WHERE fingerprint = $1 AND state = 'dismissed' ORDER BY updated_at DESC LIMIT 1`, r.Fingerprint))
			if err == nil && !material(last, r) {
				out = last
				return nil
			}
			if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
		}
		if hasLive {
			if _, err := tx.Exec(ctx, `UPDATE recommendations SET state = 'superseded', updated_at = now() WHERE id = $1`, live.ID); err != nil {
				return err
			}
			if err := resolveFinding(ctx, tx, live.FindingID, "superseded by newer advice", now); err != nil {
				return err
			}
		}
		title := fmt.Sprintf("%s %s: save about %s %s/month", actionVerb(r.Action), r.ResourceID, r.MonthlySavings, r.Currency)
		var findingID string
		if err := tx.QueryRow(ctx, `INSERT INTO findings (tenant_id, kind, fingerprint, severity, title, detail, project_id, environment_id, owner_team_id, first_seen_at)
			VALUES ($1, 'rightsizing', $2, $3, $4, $5, $6, $7, (SELECT team_id FROM projects WHERE id = $6), $8) RETURNING id::text`,
			tenant, "rightsizing:"+r.Fingerprint, severity(r.MonthlySavings, r.Currency), title,
			mustJSON(map[string]any{"current": r.Current, "recommended": r.Recommended, "evidence": r.Evidence, "monthly_savings": r.MonthlySavings, "currency": r.Currency, "source": r.Source}),
			r.ProjectID, r.EnvironmentID, now).Scan(&findingID); err != nil {
			return err
		}
		out, err = scan(tx.QueryRow(ctx, `INSERT INTO recommendations (tenant_id, fingerprint, source, provider, account_id, region, resource_id, resource_type, project_id, environment_id,
				action, current, recommended, evidence, monthly_savings, currency, savings_basis, confidence, risk, finding_id, generated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15::numeric, $16, $17, $18, $19, $20, coalesce($21, now())) RETURNING `+cols,
			tenant, r.Fingerprint, r.Source, r.Provider, r.AccountID, r.Region, r.ResourceID, r.ResourceType, r.ProjectID, r.EnvironmentID,
			r.Action, mustJSON(r.Current), mustJSON(r.Recommended), mustJSON(r.Evidence), r.MonthlySavings, r.Currency, r.SavingsBasis, r.Confidence, mustJSON(r.Risk), findingID, observed(r.ObservedAt)))
		if err != nil {
			return err
		}
		changed = true
		return record(ctx, tx, tenant, out.ID, "keel.recommendation.raised", "RaiseRecommendation", activity.Create, keelActor, title)
	})
	return out, changed, err
}

// Accept marks advice to be applied (#74 turns it into a pull request).
func (s Service) Accept(ctx context.Context, tenant, id string, by activity.Actor) (Recommendation, error) {
	return s.decide(ctx, tenant, id, "open", "accepted", "", by)
}

// Dismiss declines advice with a reason; it resurfaces only if it changes materially.
func (s Service) Dismiss(ctx context.Context, tenant, id, reason string, by activity.Actor) (Recommendation, error) {
	if reason == "" {
		return Recommendation{}, fmt.Errorf("%w: a reason is required", ErrInvalid)
	}
	return s.decide(ctx, tenant, id, "", "dismissed", reason, by)
}

func (s Service) decide(ctx context.Context, tenant, id, from, to, reason string, by activity.Actor) (Recommendation, error) {
	var out Recommendation
	err := s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		var err error
		out, err = scan(tx.QueryRow(ctx, `UPDATE recommendations SET state = $2, decided_by = $3, decision_reason = nullif($4, ''), updated_at = now()
			WHERE id = $1 AND (($5 = '' AND state IN ('open', 'accepted')) OR state = $5) RETURNING `+cols, id, to, by.UID, reason, from))
		if errors.Is(err, pgx.ErrNoRows) {
			var exists bool
			if e := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM recommendations WHERE id = $1)`, id).Scan(&exists); e == nil && exists {
				return ErrState
			}
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if to == "dismissed" {
			if err := resolveFinding(ctx, tx, out.FindingID, "dismissed: "+reason, s.now()); err != nil {
				return err
			}
		}
		return record(ctx, tx, tenant, id, "keel.recommendation."+to, "Decide", activity.Update, by, reason)
	})
	return out, err
}

// Get reads one recommendation.
func (s Service) Get(ctx context.Context, tenant, id string) (Recommendation, error) {
	var out Recommendation
	err := s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		var err error
		out, err = scan(tx.QueryRow(ctx, `SELECT `+cols+` FROM recommendations WHERE id = $1`, id))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return out, ErrNotFound
	}
	return out, err
}

// IsProduction reports whether an Environment is production, by the rule
// every engine applies: its name is prod, production or prd.
func (s Service) IsProduction(ctx context.Context, tenant, environment string) (bool, error) {
	var prod bool
	err := s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT name IN ('prod', 'production', 'prd') FROM environments WHERE id = $1`, environment).Scan(&prod)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, ErrNotFound
	}
	return prod, err
}

// SetPR links the pull request that applies a recommendation.
func (s Service) SetPR(ctx context.Context, tenant, id, url string, by activity.Actor) error {
	return s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		var finding string
		if err := tx.QueryRow(ctx, `UPDATE recommendations SET pr_url = $2, updated_at = now() WHERE id = $1 RETURNING coalesce(finding_id::text, '')`, id, url).Scan(&finding); err != nil {
			return err
		}
		if finding != "" {
			if _, err := tx.Exec(ctx, `UPDATE findings SET detail = detail || jsonb_build_object('pr_url', $2::text) WHERE id = $1`, finding, url); err != nil {
				return err
			}
		}
		return record(ctx, tx, tenant, id, "keel.recommendation.pr_opened", "OpenPullRequest", activity.Update, by, url)
	})
}

// Reopen returns an accepted recommendation to open (its PR was closed).
func (s Service) Reopen(ctx context.Context, tenant, id, why string, by activity.Actor) error {
	return s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE recommendations SET state = 'open', pr_url = NULL, updated_at = now() WHERE id = $1 AND state = 'accepted'`, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrState
		}
		return record(ctx, tx, tenant, id, "keel.recommendation.reopened", "Reopen", activity.Update, by, why)
	})
}

// Filter narrows List.
type Filter struct {
	State     string // "" = all
	ProjectID string
}

// List returns recommendations, biggest savings first.
func (s Service) List(ctx context.Context, tenant string, f Filter) ([]Recommendation, error) {
	var out []Recommendation
	err := s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+cols+` FROM recommendations WHERE ($1 = '' OR state = $1) AND ($2 = '' OR project_id::text = $2)
			ORDER BY monthly_savings DESC, generated_at DESC LIMIT 500`, f.State, f.ProjectID)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (Recommendation, error) { return scan(r) })
		return err
	})
	return out, err
}

func resolveFinding(ctx context.Context, tx pgx.Tx, id, why string, at time.Time) error {
	if id == "" {
		return nil
	}
	_, err := tx.Exec(ctx, `UPDATE findings SET status = 'resolved', resolved_at = $3, resolution = $2 WHERE id = $1 AND status = 'open'`, id, why, at)
	return err
}

func record(ctx context.Context, tx pgx.Tx, tenant, id, typ, op string, kind activity.Kind, by activity.Actor, detail string) error {
	_, err := activity.Record(ctx, tx, activity.Activity{TenantID: tenant, Source: "keel/rightsizing", Type: typ, Subject: "recommendation/" + id,
		Operation: op, Kind: kind, Actor: by, Resources: []activity.Resource{{Type: "recommendation", UID: id}}, Outcome: activity.Success, StatusDetail: detail,
		Why: activity.Why{Reason: detail}})
	return err
}

func observed(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// MarkApplied records that a recommendation was carried out (a merged pull
// request, or Keel's own cleanup), resolving its Finding.
func (s Service) MarkApplied(ctx context.Context, tenant, id, note, prURL string, by activity.Actor) error {
	now := s.now()
	return s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		var finding string
		err := tx.QueryRow(ctx, `UPDATE recommendations SET state = 'applied', decided_by = $2, decision_reason = $3, pr_url = coalesce(nullif($4, ''), pr_url), updated_at = now(), applied_at = $5
			WHERE id = $1 AND state IN ('open', 'accepted') RETURNING coalesce(finding_id::text, '')`, id, by.UID, note, prURL, now).Scan(&finding)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrState
		}
		if err != nil {
			return err
		}
		if err := resolveFinding(ctx, tx, finding, "applied: "+note, now); err != nil {
			return err
		}
		return record(ctx, tx, tenant, id, "keel.recommendation.applied", "ApplyRecommendation", activity.Update, by, note)
	})
}

func mustJSON(v any) []byte {
	if v == nil {
		return []byte("{}")
	}
	b, _ := json.Marshal(v)
	return b
}

func actionVerb(a string) string {
	switch a {
	case "resize_requests":
		return "Right-size requests of"
	case "resize", "change_family":
		return "Resize"
	case "schedule":
		return "Schedule off-hours stop for"
	case "delete":
		return "Delete"
	case "stop", "schedule_offhours":
		return "Schedule off-hours for"
	}
	return "Optimise"
}
