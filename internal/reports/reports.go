// Package reports builds each Tenant's monthly report (#152) from its own
// data: spend against budget per Project with the year-end forecast, savings
// realised, DORA, Findings by severity and SLA, Exceptions and access grants.
// A report is stored as data and as a self-contained HTML page, so it reads
// the same later even after the underlying figures move.
package reports

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/budget"
	"github.com/hx-thanadej/keel/internal/dora"
	"github.com/hx-thanadej/keel/internal/rightsize"
	"github.com/hx-thanadej/keel/internal/store"
)

// Report is one Tenant's month.
type Report struct {
	Tenant      string         `json:"tenant"`
	TenantName  string         `json:"tenant_name"`
	Period      string         `json:"period"` // YYYY-MM
	GeneratedAt time.Time      `json:"generated_at"`
	Final       bool           `json:"final"` // every Budget line's cost data is final
	Currency    string         `json:"currency"`
	Budgets     []BudgetLine   `json:"budgets"`
	Savings     Savings        `json:"savings"`
	DORA        dora.Metrics   `json:"dora"`
	Services    []dora.Metrics `json:"dora_services"`
	Findings    Findings       `json:"findings"`
	Exceptions  Exceptions     `json:"exceptions"`
	Access      Access         `json:"access"`
}

// BudgetLine is one Budget: the month against its share, and the year.
type BudgetLine struct {
	Project        string `json:"project"`
	Budget         string `json:"budget"`
	Currency       string `json:"currency"`
	MonthBudget    string `json:"month_budget"`
	MonthActual    string `json:"month_actual"`
	MonthVariance  string `json:"month_variance"`
	YearBudget     string `json:"year_budget"`
	YearToDate     string `json:"year_to_date"`
	Forecast       string `json:"forecast"` // p50 at year end; "" without enough history
	ForecastMethod string `json:"forecast_method"`
	Final          bool   `json:"final"`
	MissingFX      bool   `json:"missing_fx"`
}

// Savings realised from applied recommendations.
type Savings struct {
	Currency    string                  `json:"currency"`
	Realised    string                  `json:"realised_monthly"`
	Applied     string                  `json:"applied_monthly"`
	Regressions int                     `json:"regressions"`
	Top         []rightsize.SavingsItem `json:"top"`
}

// Findings at month end and movement during it.
type Findings struct {
	OpenBySeverity map[string]int `json:"open_by_severity"`
	Overdue        int            `json:"overdue"`
	Raised         int            `json:"raised"`
	Resolved       int            `json:"resolved"`
	WithinSLA      int            `json:"resolved_within_sla"`
}

// Exceptions active during the month.
type Exceptions struct {
	Active   int `json:"active"`
	Granted  int `json:"granted_in_period"`
	Expiring int `json:"expiring_next_30_days"`
}

// Access grants requested during the month.
type Access struct {
	Requested int            `json:"requested"`
	ByState   map[string]int `json:"by_state"`
	Hours     int            `json:"hours_granted"`
}

// Summary lists stored reports.
type Summary struct {
	Period      string    `json:"period"`
	GeneratedAt time.Time `json:"generated_at"`
}

// Service generates and serves reports.
type Service struct {
	Store   *store.Store
	Budgets budget.Service
	DORA    dora.Service
	Savings rightsize.Tracker
	Now     func() time.Time
}

var (
	ErrNotFound = errors.New("report not found")
	ErrPeriod   = errors.New("period is YYYY-MM and must be a finished month")
)

var keelActor = activity.Actor{Type: activity.ActorKeel, UID: "keel:reports"}

func (s Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

// ParsePeriod reads YYYY-MM as the first instant of that month.
func ParsePeriod(v string) (time.Time, error) {
	t, err := time.Parse("2006-01", v)
	if err != nil {
		return time.Time{}, ErrPeriod
	}
	return t, nil
}

// Run generates last month's report for every Tenant that lacks one, and
// regenerates any whose cost data was not yet final. It is safe to run
// hourly and from several replicas: on the first of a month it produces the
// new reports, later runs fill in any a failed run missed and refresh
// provisional figures, and each report change is recorded once.
func (s Service) Run(ctx context.Context) (int, error) {
	n := s.now()
	period := time.Date(n.Year(), n.Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, -1, 0)
	rows, err := s.Store.AppPool().Query(ctx, `SELECT t::text FROM tenant_ids() AS t`)
	if err != nil {
		return 0, err
	}
	tenants, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return 0, err
	}
	made := 0
	var errs []error
	for _, tenant := range tenants {
		var exists, final bool
		if err := s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) > 0, coalesce(bool_and((data->>'final')::boolean), false) FROM tenant_reports WHERE period = $1`, period).Scan(&exists, &final)
		}); err != nil {
			errs = append(errs, fmt.Errorf("tenant %s: %w", tenant, err))
			continue
		}
		if final {
			continue
		}
		w := create
		if exists {
			w = refresh
		}
		_, changed, err := s.generate(ctx, tenant, period, keelActor, w)
		if err != nil {
			errs = append(errs, fmt.Errorf("tenant %s: %w", tenant, err))
			continue
		}
		if changed {
			made++
		}
	}
	return made, errors.Join(errs...)
}

// write says how a newly generated report meets one already stored for its
// month.
type write int

const (
	create  write = iota // keep the stored one: another run got there first
	refresh              // replace it only if its figures moved
	replace              // always replace it
)

var upsert = map[write]string{
	create:  `DO NOTHING`,
	refresh: `DO UPDATE SET generated_at = excluded.generated_at, data = excluded.data, html = excluded.html WHERE tenant_reports.data - 'generated_at' IS DISTINCT FROM excluded.data - 'generated_at'`,
	replace: `DO UPDATE SET generated_at = excluded.generated_at, data = excluded.data, html = excluded.html`,
}

// Generate builds, stores and returns the report for the month starting at
// period, replacing any earlier one for that month.
func (s Service) Generate(ctx context.Context, tenant string, period time.Time, by activity.Actor) (Report, error) {
	r, _, err := s.generate(ctx, tenant, period, by, replace)
	return r, err
}

// generate builds the report and stores it as w says, reporting whether the
// stored report was created or changed. Only a change is an Activity.
func (s Service) generate(ctx context.Context, tenant string, period time.Time, by activity.Actor, w write) (Report, bool, error) {
	from := time.Date(period.Year(), period.Month(), 1, 0, 0, 0, 0, time.UTC)
	to := from.AddDate(0, 1, 0)
	if to.After(s.now()) {
		return Report{}, false, ErrPeriod
	}
	last := to.AddDate(0, 0, -1)
	r := Report{Tenant: tenant, Period: from.Format("2006-01"), GeneratedAt: s.now()}
	if err := s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT name, currency FROM tenants WHERE id = $1`, tenant).Scan(&r.TenantName, &r.Currency)
	}); err != nil {
		return r, false, err
	}

	budgets, err := s.Budgets.List(ctx, tenant, "")
	if err != nil {
		return r, false, err
	}
	projects := map[string]string{}
	if err := s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id::text, name FROM projects`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id, name string
			if err := rows.Scan(&id, &name); err != nil {
				return err
			}
			projects[id] = name
		}
		return rows.Err()
	}); err != nil {
		return r, false, err
	}
	for _, b := range budgets {
		if b.Year != from.Year() {
			continue
		}
		m, err := s.Budgets.Status(ctx, tenant, b.ID, budget.Month, last)
		if err != nil {
			return r, false, fmt.Errorf("budget %s: %w", b.Name, err)
		}
		y, err := s.Budgets.Status(ctx, tenant, b.ID, budget.Year, last)
		if err != nil {
			return r, false, fmt.Errorf("budget %s: %w", b.Name, err)
		}
		r.Budgets = append(r.Budgets, BudgetLine{Project: projects[b.ProjectID], Budget: b.Name, Currency: b.Currency,
			MonthBudget: m.Budget, MonthActual: m.Actual, MonthVariance: sub(m.Actual, m.Budget),
			YearBudget: y.Budget, YearToDate: y.Actual, Forecast: y.Forecast, ForecastMethod: y.ForecastMethod,
			Final: m.Final, MissingFX: m.MissingFX || y.MissingFX})
	}
	sort.SliceStable(r.Budgets, func(i, j int) bool { return r.Budgets[i].Project < r.Budgets[j].Project })
	r.Final = true
	for _, b := range r.Budgets {
		r.Final = r.Final && b.Final
	}

	sv, err := s.Savings.Summary(ctx, tenant, "")
	if err != nil {
		return r, false, err
	}
	r.Savings = Savings{Currency: sv.Currency, Realised: sv.Realised, Applied: sv.Applied, Regressions: sv.Regressions}
	for _, it := range sv.Items {
		if it.Realised != nil && it.AppliedAt.Before(to) {
			r.Savings.Top = append(r.Savings.Top, it)
		}
	}
	sort.SliceStable(r.Savings.Top, func(i, j int) bool {
		return rat(*r.Savings.Top[i].Realised).Cmp(rat(*r.Savings.Top[j].Realised)) > 0
	})
	if len(r.Savings.Top) > 5 {
		r.Savings.Top = r.Savings.Top[:5]
	}

	d, err := s.DORA.Compute(ctx, tenant, from, to)
	if err != nil {
		return r, false, err
	}
	r.DORA, r.Services = d.Tenant, d.Services

	err = s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		var sev []byte
		if err := tx.QueryRow(ctx, `SELECT coalesce(jsonb_object_agg(severity, n), '{}') FROM (
				SELECT severity, count(*) n FROM findings WHERE first_seen_at < $1 AND (resolved_at IS NULL OR resolved_at >= $1) GROUP BY severity) a`, to).Scan(&sev); err != nil {
			return err
		}
		if err := json.Unmarshal(sev, &r.Findings.OpenBySeverity); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT
				(SELECT count(*) FROM findings WHERE first_seen_at < $2 AND (resolved_at IS NULL OR resolved_at >= $2) AND due_at < $2),
				(SELECT count(*) FROM findings WHERE first_seen_at >= $1 AND first_seen_at < $2),
				(SELECT count(*) FROM findings WHERE resolved_at >= $1 AND resolved_at < $2),
				(SELECT count(*) FROM findings WHERE resolved_at >= $1 AND resolved_at < $2 AND (due_at IS NULL OR resolved_at <= due_at)),
				(SELECT count(*) FROM exceptions WHERE state IN ('approved', 'expired', 'revoked')
					AND coalesce(approved_at, decided_at, created_at) < $2 AND coalesce(revoked_at, expires_at) >= $1),
				(SELECT count(*) FROM exceptions WHERE approved_at >= $1 AND approved_at < $2),
				(SELECT count(*) FROM exceptions WHERE state = 'approved' AND expires_at >= $2 AND expires_at < $2 + interval '30 days'),
				(SELECT count(*) FROM access_grants WHERE created_at >= $1 AND created_at < $2),
				(SELECT coalesce(sum(hours) FILTER (WHERE activated_at IS NOT NULL), 0) FROM access_grants WHERE created_at >= $1 AND created_at < $2)`, from, to).
			Scan(&r.Findings.Overdue, &r.Findings.Raised, &r.Findings.Resolved, &r.Findings.WithinSLA,
				&r.Exceptions.Active, &r.Exceptions.Granted, &r.Exceptions.Expiring, &r.Access.Requested, &r.Access.Hours); err != nil {
			return err
		}
		var states []byte
		if err := tx.QueryRow(ctx, `SELECT coalesce(jsonb_object_agg(state, n), '{}') FROM (
				SELECT state, count(*) n FROM access_grants WHERE created_at >= $1 AND created_at < $2 GROUP BY state) a`, from, to).Scan(&states); err != nil {
			return err
		}
		return json.Unmarshal(states, &r.Access.ByState)
	})
	if err != nil {
		return r, false, err
	}

	var page bytes.Buffer
	if err := pageTmpl.Execute(&page, r); err != nil {
		return r, false, err
	}
	data, err := json.Marshal(r)
	if err != nil {
		return r, false, err
	}
	changed := false
	err = s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		var inserted bool // xmax is 0 only on a row this statement inserted
		err := tx.QueryRow(ctx, `INSERT INTO tenant_reports (tenant_id, period, generated_at, data, html) VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (tenant_id, period) `+upsert[w]+` RETURNING xmax = 0`,
			tenant, from, r.GeneratedAt, data, page.String()).Scan(&inserted)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		changed = true
		kind := activity.Update
		if inserted {
			kind = activity.Create
		}
		_, err = activity.Record(ctx, tx, activity.Activity{TenantID: tenant, Source: "keel/reports", Type: "keel.report.generated",
			Subject: "tenant/" + tenant + "/reports/" + r.Period, Operation: "GenerateReport", Kind: kind, Actor: by,
			Outcome: activity.Success, StatusDetail: fmt.Sprintf("monthly report %s: %d budgets, %d deployments, final %v", r.Period, len(r.Budgets), r.DORA.Deployments, r.Final)})
		return err
	})
	return r, changed, err
}

// List returns stored reports, newest first.
func (s Service) List(ctx context.Context, tenant string) ([]Summary, error) {
	var out []Summary
	err := s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT to_char(period, 'YYYY-MM'), generated_at FROM tenant_reports ORDER BY period DESC`)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, pgx.RowToStructByPos[Summary])
		return err
	})
	if out == nil {
		out = []Summary{}
	}
	return out, err
}

// Get returns one stored report as data and HTML.
func (s Service) Get(ctx context.Context, tenant string, period time.Time) (Report, string, error) {
	var r Report
	var raw []byte
	var page string
	err := s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT data, html FROM tenant_reports WHERE period = $1`, period).Scan(&raw, &page)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return r, "", ErrNotFound
	}
	if err != nil {
		return r, "", err
	}
	return r, page, json.Unmarshal(raw, &r)
}

func rat(s string) *big.Rat {
	r, ok := new(big.Rat).SetString(s)
	if !ok {
		return new(big.Rat)
	}
	return r
}

func sub(a, b string) string { return new(big.Rat).Sub(rat(a), rat(b)).FloatString(2) }

func fmtFloat(v float64, prec int) string { return strconv.FormatFloat(v, 'f', prec, 64) }

// SystemActor is Keel itself, for scheduled generation.
func SystemActor() activity.Actor { return keelActor }
