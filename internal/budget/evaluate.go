package budget

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
)

// Alert is a newly crossed threshold.
type Alert struct {
	TenantID string `json:"tenant_id"`
	BudgetID string `json:"budget_id"`
	Name     string `json:"budget_name"`
	Month    string `json:"month"`
	Pct      string `json:"pct"`
	Basis    string `json:"basis"`
	Value    string `json:"value"`
	Budget   string `json:"month_budget"`
	Currency string `json:"currency"`
	Final    bool   `json:"data_final"`
}

// Evaluator checks every active Budget's current month after each cost load
// and hourly. Each threshold fires at most once per Budget and month.
type Evaluator struct {
	Service Service
	Now     func() time.Time
	HTTP    *http.Client
}

// EvaluateAll returns the thresholds newly crossed.
func (e Evaluator) EvaluateAll(ctx context.Context) ([]Alert, error) {
	now := time.Now
	if e.Now != nil {
		now = e.Now
	}
	asOf := now().UTC()
	rows, err := e.Service.Store.AppPool().Query(ctx, `SELECT t::text FROM tenant_ids() AS t`)
	if err != nil {
		return nil, err
	}
	tenants, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}
	var out []Alert
	for _, t := range tenants {
		budgets, err := e.Service.List(ctx, t, "")
		if err != nil {
			return out, err
		}
		for _, b := range budgets {
			if b.Year != asOf.Year() {
				continue
			}
			st, err := e.Service.Status(ctx, t, b.ID, Month, asOf)
			if err != nil {
				return out, err
			}
			alerts, err := e.raise(ctx, b, st)
			if err != nil {
				return out, err
			}
			out = append(out, alerts...)
		}
	}
	return out, nil
}

func (e Evaluator) raise(ctx context.Context, b Budget, st Status) ([]Alert, error) {
	month := rat(st.Budget)
	var out []Alert
	for _, th := range b.Thresholds {
		value := st.Actual
		if th.Basis == "forecast" {
			value = st.Forecast
		}
		limit := new(big.Rat).Mul(month, new(big.Rat).SetFloat64(th.Pct/100))
		if value == "" || rat(value).Cmp(limit) < 0 {
			continue
		}
		a := Alert{TenantID: b.TenantID, BudgetID: b.ID, Name: b.Name, Month: st.Start.Format("2006-01"), Pct: pct(th.Pct), Basis: th.Basis,
			Value: value, Budget: st.Budget, Currency: st.Currency, Final: st.Final}
		inserted := false
		err := e.Service.Store.InTenant(ctx, b.TenantID, func(tx pgx.Tx) error {
			var id string
			err := tx.QueryRow(ctx, `INSERT INTO budget_alerts (tenant_id, budget_id, month, pct, basis, value, budget_amount)
				VALUES ($1, $2, $3, $4, $5, $6::numeric, $7::numeric) ON CONFLICT (budget_id, month, pct, basis) DO NOTHING RETURNING id::text`,
				b.TenantID, b.ID, st.Start, th.Pct, th.Basis, value, st.Budget).Scan(&id)
			if err == pgx.ErrNoRows {
				return nil
			}
			if err != nil {
				return err
			}
			inserted = true
			_, err = activity.Record(ctx, tx, activity.Activity{TenantID: b.TenantID, Source: "keel/budget", Type: "keel.budget.threshold_crossed",
				Subject: "budget/" + b.ID, Operation: "EvaluateBudget", Kind: activity.Other, Actor: keelActor,
				Resources: []activity.Resource{{Type: "budget", UID: b.ID}}, Outcome: activity.Success,
				StatusDetail: fmt.Sprintf("%s %s ≥ %s%% of %s %s budget for %s (data final: %v)", th.Basis, value, a.Pct, st.Budget, st.Currency, a.Month, st.Final)})
			return err
		})
		if err != nil {
			return out, err
		}
		if inserted {
			out = append(out, a)
			if b.WebhookURL != nil {
				e.notify(ctx, *b.WebhookURL, a)
			}
		}
	}
	return out, nil
}

// notify posts the alert as JSON. Best effort: failures are logged, the alert
// itself is already recorded.
func (e Evaluator) notify(ctx context.Context, url string, a Alert) {
	c := e.HTTP
	if c == nil {
		c = &http.Client{Timeout: 10 * time.Second}
	}
	body, _ := json.Marshal(map[string]any{"text": fmt.Sprintf("Keel budget %q: %s spend %s %s reached %s%% of the %s budget %s (%s)",
		a.Name, a.Basis, a.Value, a.Currency, a.Pct, a.Month, a.Budget, map[bool]string{true: "final data", false: "data not final"}[a.Final]), "alert": a})
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		slog.Error("budget webhook", "err", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := c.Do(req)
	if err != nil {
		slog.Error("budget webhook failed", "budget", a.BudgetID, "err", err)
		return
	}
	_ = res.Body.Close()
	if res.StatusCode >= 300 {
		slog.Error("budget webhook rejected", "budget", a.BudgetID, "status", res.StatusCode)
	}
}
