// Package budget implements Budgets per Project or Project × Environment,
// phased from a yearly amount into months and days, evaluated against actual
// and forecast spend in the Tenant's currency (#36, #37, #43; ADR-0012).
package budget

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/store"
)

// Errors mapped by the API layer.
var (
	ErrInvalid  = errors.New("invalid budget")
	ErrConflict = errors.New("a budget already exists for this scope and year")
	ErrNotFound = errors.New("budget not found")
)

// Threshold raises an alert when actual or forecast month spend reaches Pct%
// of the month's budget.
type Threshold struct {
	Pct   float64 `json:"pct"`
	Basis string  `json:"basis"` // actual | forecast
}

// Budget is a yearly amount for a Project (optionally one Environment and/or provider).
type Budget struct {
	ID             string      `json:"id"`
	TenantID       string      `json:"tenant_id"`
	ProjectID      string      `json:"project_id"`
	EnvironmentID  *string     `json:"environment_id"`
	Provider       *string     `json:"provider"`
	Name           string      `json:"name"`
	Year           int         `json:"year"`
	Amount         string      `json:"amount"`
	Currency       string      `json:"currency"`
	MonthlyWeights []string    `json:"monthly_weights"` // 12 weights; nil = by days in month
	CostBasis      string      `json:"cost_basis"`      // effective | billed
	Thresholds     []Threshold `json:"thresholds"`
	WebhookURL     *string     `json:"webhook_url,omitempty"`
	CreatedAt      time.Time   `json:"created_at"`
}

func rat(s string) *big.Rat {
	r, ok := new(big.Rat).SetString(s)
	if !ok {
		return new(big.Rat)
	}
	return r
}

func money(r *big.Rat) string { return r.FloatString(2) }

func daysIn(year int, m time.Month) int {
	return time.Date(year, m+1, 0, 0, 0, 0, 0, time.UTC).Day()
}

func (b Budget) monthRat(m time.Month) *big.Rat {
	total := rat(b.Amount)
	if len(b.MonthlyWeights) == 12 {
		sum := new(big.Rat)
		for _, w := range b.MonthlyWeights {
			sum.Add(sum, rat(w))
		}
		if sum.Sign() > 0 {
			return new(big.Rat).Quo(new(big.Rat).Mul(total, rat(b.MonthlyWeights[m-1])), sum)
		}
	}
	daysInYear := time.Date(b.Year, 12, 31, 0, 0, 0, 0, time.UTC).YearDay()
	return new(big.Rat).Quo(new(big.Rat).Mul(total, big.NewRat(int64(daysIn(b.Year, m)), 1)), big.NewRat(int64(daysInYear), 1))
}

func (b Budget) dayRat(day time.Time) *big.Rat {
	return new(big.Rat).Quo(b.monthRat(day.Month()), big.NewRat(int64(daysIn(day.Year(), day.Month())), 1))
}

// MonthAmount is the month's share of the yearly amount.
func (b Budget) MonthAmount(m time.Month) string { return money(b.monthRat(m)) }

// DayAmount is the day's share of its month.
func (b Budget) DayAmount(day time.Time) string { return money(b.dayRat(day)) }

func (b *Budget) validate() error {
	if b.Name == "" || b.Year < 2000 || b.Year > 2100 {
		return fmt.Errorf("%w: name and a year between 2000 and 2100 are required", ErrInvalid)
	}
	if r, ok := new(big.Rat).SetString(b.Amount); !ok || r.Sign() <= 0 {
		return fmt.Errorf("%w: amount must be a positive decimal", ErrInvalid)
	}
	if b.MonthlyWeights != nil && len(b.MonthlyWeights) != 12 {
		return fmt.Errorf("%w: monthly_weights needs 12 values", ErrInvalid)
	}
	for _, w := range b.MonthlyWeights {
		if r, ok := new(big.Rat).SetString(w); !ok || r.Sign() <= 0 {
			return fmt.Errorf("%w: monthly weights must be positive decimals", ErrInvalid)
		}
	}
	if b.CostBasis == "" {
		b.CostBasis = "effective"
	}
	if b.CostBasis != "effective" && b.CostBasis != "billed" {
		return fmt.Errorf("%w: cost_basis is effective or billed", ErrInvalid)
	}
	if b.Thresholds == nil {
		b.Thresholds = []Threshold{{80, "actual"}, {100, "actual"}, {100, "forecast"}}
	}
	for _, t := range b.Thresholds {
		if t.Pct <= 0 || t.Pct > 1000 || (t.Basis != "actual" && t.Basis != "forecast") {
			return fmt.Errorf("%w: thresholds need pct in (0,1000] and basis actual|forecast", ErrInvalid)
		}
	}
	return nil
}

// Service stores and evaluates Budgets. Authorisation is the API layer's job.
type Service struct {
	Store *store.Store
}

const cols = `id::text, tenant_id::text, project_id::text, environment_id::text, provider, name, year, amount::text, currency,
	monthly_weights::text[], cost_basis, thresholds, webhook_url, created_at`

func scan(r pgx.Row) (Budget, error) {
	var b Budget
	var th []byte
	err := r.Scan(&b.ID, &b.TenantID, &b.ProjectID, &b.EnvironmentID, &b.Provider, &b.Name, &b.Year, &b.Amount, &b.Currency,
		&b.MonthlyWeights, &b.CostBasis, &th, &b.WebhookURL, &b.CreatedAt)
	if err == nil {
		err = json.Unmarshal(th, &b.Thresholds)
	}
	return b, err
}

// Create adds a Budget in the Tenant's currency.
func (s Service) Create(ctx context.Context, tenantID string, b Budget, by ...activity.Actor) (Budget, error) {
	if err := b.validate(); err != nil {
		return Budget{}, err
	}
	th, _ := json.Marshal(b.Thresholds)
	var out Budget
	err := s.Store.InTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		out, err = scan(tx.QueryRow(ctx, `INSERT INTO budgets (tenant_id, project_id, environment_id, provider, name, year, amount, currency, monthly_weights, cost_basis, thresholds, webhook_url)
			VALUES ($1, $2, $3, $4, $5, $6, $7::numeric, (SELECT currency FROM tenants WHERE id = $1), $8::numeric[], $9, $10, $11) RETURNING `+cols,
			tenantID, b.ProjectID, b.EnvironmentID, b.Provider, b.Name, b.Year, b.Amount, b.MonthlyWeights, b.CostBasis, th, b.WebhookURL))
		if err != nil {
			return err
		}
		return record(ctx, tx, tenantID, out.ID, "keel.budget.created", "CreateBudget", activity.Create, by,
			fmt.Sprintf("%s %s for %d", out.Amount, out.Currency, out.Year))
	})
	return out, mapErr(err)
}

// Update changes amount, name, weights, thresholds or webhook.
func (s Service) Update(ctx context.Context, tenantID, id string, b Budget, by ...activity.Actor) (Budget, error) {
	if err := b.validate(); err != nil {
		return Budget{}, err
	}
	th, _ := json.Marshal(b.Thresholds)
	var out Budget
	err := s.Store.InTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		out, err = scan(tx.QueryRow(ctx, `UPDATE budgets SET name = $2, amount = $3::numeric, monthly_weights = $4::numeric[], cost_basis = $5, thresholds = $6, webhook_url = $7
			WHERE id = $1 AND archived_at IS NULL RETURNING `+cols, id, b.Name, b.Amount, b.MonthlyWeights, b.CostBasis, th, b.WebhookURL))
		if err != nil {
			return err
		}
		return record(ctx, tx, tenantID, id, "keel.budget.updated", "UpdateBudget", activity.Update, by, fmt.Sprintf("amount %s %s", out.Amount, out.Currency))
	})
	return out, mapErr(err)
}

// Archive retires a Budget.
func (s Service) Archive(ctx context.Context, tenantID, id string, by ...activity.Actor) error {
	return mapErr(s.Store.InTenant(ctx, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE budgets SET archived_at = now() WHERE id = $1 AND archived_at IS NULL`, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return record(ctx, tx, tenantID, id, "keel.budget.archived", "ArchiveBudget", activity.Update, by, "")
	}))
}

// Get reads one active Budget.
func (s Service) Get(ctx context.Context, tenantID, id string) (Budget, error) {
	var b Budget
	err := s.Store.InTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		b, err = scan(tx.QueryRow(ctx, `SELECT `+cols+` FROM budgets WHERE id = $1 AND archived_at IS NULL`, id))
		return err
	})
	return b, mapErr(err)
}

// List returns active Budgets, optionally for one Project.
func (s Service) List(ctx context.Context, tenantID, projectID string) ([]Budget, error) {
	var out []Budget
	err := s.Store.InTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+cols+` FROM budgets WHERE archived_at IS NULL AND ($1 = '' OR project_id::text = $1) ORDER BY year DESC, name`, projectID)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (Budget, error) { return scan(r) })
		return err
	})
	return out, mapErr(err)
}

var keelActor = activity.Actor{Type: activity.ActorKeel, UID: "keel:budget"}

func record(ctx context.Context, tx pgx.Tx, tenant, id, typ, op string, kind activity.Kind, by []activity.Actor, detail string) error {
	a := keelActor
	if len(by) > 0 {
		a = by[0]
	}
	_, err := activity.Record(ctx, tx, activity.Activity{TenantID: tenant, Source: "keel/budget", Type: typ, Subject: "budget/" + id,
		Operation: op, Kind: kind, Actor: a, Resources: []activity.Resource{{Type: "budget", UID: id}}, Outcome: activity.Success, StatusDetail: detail})
	return err
}

func mapErr(err error) error {
	var pgErr *pgconn.PgError
	switch {
	case err == nil:
		return nil
	case errors.Is(err, pgx.ErrNoRows):
		return ErrNotFound
	case errors.As(err, &pgErr) && pgErr.Code == "23505":
		return ErrConflict
	case errors.As(err, &pgErr) && (pgErr.Code == "23503" || pgErr.Code == "23514" || pgErr.Code == "22P02"):
		return fmt.Errorf("%w: %s", ErrInvalid, pgErr.Message)
	}
	return err
}

func pct(p float64) string { return strconv.FormatFloat(p, 'f', -1, 64) }
