// Package clientreads lands what Keel reads through a client payer's
// read-only role, other than bills, in that payer's Tenant (ADR-0018):
// Budget status, security Findings and Rightsizing Recommendations.
package clientreads

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/cost"
	"github.com/hx-thanadej/keel/internal/findings"
	"github.com/hx-thanadej/keel/internal/rightsize"
	"github.com/hx-thanadej/keel/internal/store"
)

// Budget is one of the client's own cloud budgets as its provider reports
// it. Limit, Actual and Forecast are decimals in Unit; an empty Limit means
// the budget has no limit for the current period.
type Budget struct {
	Name                    string
	Limit, Actual, Forecast string
	Unit                    string
}

// Finding is one active security finding the client's cloud reports.
// Severity is low, medium, high or critical.
type Finding struct {
	ID       string // the provider's finding id, unique within the payer
	Account  string // the account the finding is about
	Severity string
	Title    string
	Source   string // the product that raised it, e.g. Security Hub or Config
	Resource string
}

// Reader reads one client payer through its read-only role. Each method is
// one independent source; one failing does not stop the others.
type Reader interface {
	Budgets(context.Context) ([]Budget, error)
	Findings(context.Context) ([]Finding, error)
	Recommendations(context.Context) ([]rightsize.Recommendation, error)
}

// Sync reads every client payer it is given and lands the results in that
// payer's Tenant only.
type Sync struct {
	Store    *store.Store
	Provider string
	// Connect assumes the payer's read-only role and returns a Reader that
	// makes only read calls with it.
	Connect func(cost.ClientPayer) (Reader, error)
	Now     func() time.Time
}

// Report counts one payer's run. Dropped counts findings and
// recommendations for accounts outside the payer's Tenant.
type Report struct {
	Payer           cost.ClientPayer `json:"-"`
	Budgets         int              `json:"budgets"`
	BudgetsOver     int              `json:"budgets_over"`
	Findings        int              `json:"findings"`
	Recommendations int              `json:"recommendations"`
	Dropped         int              `json:"dropped"`
}

// Run reads each payer. One payer's or one source's failure does not stop
// the others; the errors are joined. A failed source resolves nothing, so
// its Findings stay as last read.
func (s *Sync) Run(ctx context.Context, payers []cost.ClientPayer) ([]Report, error) {
	var out []Report
	var failed []error
	for _, p := range payers {
		rep, err := s.one(ctx, p)
		if err != nil {
			failed = append(failed, fmt.Errorf("client payer %s (tenant %s): %w", p.PayerID, p.TenantID, err))
		}
		out = append(out, rep)
	}
	return out, errors.Join(failed...)
}

func (s *Sync) one(ctx context.Context, p cost.ClientPayer) (Report, error) {
	rep := Report{Payer: p}
	r, err := s.Connect(p)
	if err != nil {
		return rep, err
	}
	var failed []error
	if budgets, err := r.Budgets(ctx); err != nil {
		failed = append(failed, fmt.Errorf("budgets: %w", err))
	} else if err := s.budgets(ctx, p, budgets, &rep); err != nil {
		return rep, err
	}
	if fs, err := r.Findings(ctx); err != nil {
		failed = append(failed, fmt.Errorf("findings: %w", err))
	} else if err := s.findings(ctx, p, fs, &rep); err != nil {
		return rep, err
	}
	if recs, err := r.Recommendations(ctx); err != nil {
		failed = append(failed, fmt.Errorf("recommendations: %w", err))
	} else {
		res, err := (rightsize.Service{Store: s.Store}).ImportForClient(ctx, p.TenantID, recs)
		if err != nil {
			return rep, err
		}
		rep.Recommendations = res.Raised + res.Kept
		rep.Dropped += res.Dropped
	}
	return rep, errors.Join(failed...)
}

func (s *Sync) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// prefix starts every fingerprint of kind for payer p, so one read resolves
// only that payer's Findings of that kind.
func (s *Sync) prefix(kind findings.Kind, p cost.ClientPayer) string {
	return kind.String() + ":" + s.Provider + "/" + p.PayerID + "/"
}

// over says how a budget stands against its limit: actual spend over it is
// high, a forecast over it is medium, anything else raises nothing.
func over(b Budget) (severity, why string) {
	limit, ok := new(big.Rat).SetString(b.Limit)
	if !ok || limit.Sign() <= 0 {
		return "", ""
	}
	if a, ok := new(big.Rat).SetString(b.Actual); ok && a.Cmp(limit) > 0 {
		return "high", "spend " + b.Actual + " " + b.Unit + " is over the limit " + b.Limit
	}
	if f, ok := new(big.Rat).SetString(b.Forecast); ok && f.Cmp(limit) > 0 {
		return "medium", "forecast " + b.Forecast + " " + b.Unit + " is over the limit " + b.Limit
	}
	return "", ""
}

// budgets keeps one open Finding per budget over its limit or forecast to
// be, in the payer's Tenant. The budget is the payer's own object, so it
// belongs to the payer's Tenant whatever accounts it covers.
func (s *Sync) budgets(ctx context.Context, p cost.ClientPayer, budgets []Budget, rep *Report) error {
	rep.Budgets = len(budgets)
	prefix := s.prefix(findings.CloudBudget, p)
	return s.Store.InTenant(ctx, p.TenantID, func(tx pgx.Tx) error {
		seen := []string{}
		for _, b := range budgets {
			severity, why := over(b)
			if severity == "" {
				continue
			}
			rep.BudgetsOver++
			fp := prefix + b.Name
			seen = append(seen, fp)
			detail, _ := json.Marshal(map[string]string{"provider": s.Provider, "payer": p.PayerID, "cloud_account_id": p.CloudAccountID,
				"budget": b.Name, "limit": b.Limit, "actual": b.Actual, "forecast": b.Forecast, "unit": b.Unit, "reason": why})
			if _, err := tx.Exec(ctx, `INSERT INTO findings (tenant_id, kind, fingerprint, severity, title, detail, first_seen_at)
				VALUES ($1, $2, $3, $4, $5, $6, $7)
				ON CONFLICT (tenant_id, fingerprint) WHERE status = 'open' DO UPDATE SET last_seen_at = excluded.first_seen_at, severity = excluded.severity, detail = excluded.detail`,
				p.TenantID, findings.CloudBudget, fp, severity, fmt.Sprintf("%s budget %s in %s: %s", s.Provider, b.Name, p.PayerID, why), detail, s.now()); err != nil {
				return err
			}
		}
		return s.resolveGone(ctx, tx, findings.CloudBudget, prefix, seen, "budget no longer over its limit")
	})
}

var severities = map[string]bool{"low": true, "medium": true, "high": true, "critical": true}

// findings keeps one open Finding per active security finding on one of the
// payer Tenant's client-owned accounts, with that account's Project and
// Environment. A finding on any other account is dropped and counted.
func (s *Sync) findings(ctx context.Context, p cost.ClientPayer, fs []Finding, rep *Report) error {
	type owner struct{ project, env *string }
	owners := map[string]owner{}
	var ids []string
	for _, f := range fs {
		ids = append(ids, f.Account)
	}
	rows, err := s.Store.AppPool().Query(ctx, `SELECT external_id, project_id::text, environment_id::text FROM account_owners($1, $2)
		WHERE ownership = 'client' AND tenant_id = $3`, s.Provider, ids, p.TenantID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var ext string
		var o owner
		if err := rows.Scan(&ext, &o.project, &o.env); err != nil {
			rows.Close()
			return err
		}
		owners[ext] = o
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	prefix := s.prefix(findings.CloudSecurity, p)
	return s.Store.InTenant(ctx, p.TenantID, func(tx pgx.Tx) error {
		seen := []string{}
		for _, f := range fs {
			o, ok := owners[f.Account]
			if !ok {
				rep.Dropped++
				continue
			}
			if !severities[f.Severity] {
				continue
			}
			rep.Findings++
			fp := prefix + f.ID
			seen = append(seen, fp)
			detail, _ := json.Marshal(map[string]string{"provider": s.Provider, "payer": p.PayerID, "account": f.Account,
				"finding_id": f.ID, "source": f.Source, "resource": f.Resource})
			if _, err := tx.Exec(ctx, `INSERT INTO findings (tenant_id, kind, fingerprint, severity, title, detail, project_id, environment_id, owner_team_id, first_seen_at)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, (SELECT team_id FROM projects WHERE id = $7), $9)
				ON CONFLICT (tenant_id, fingerprint) WHERE status = 'open' DO UPDATE SET last_seen_at = excluded.first_seen_at, severity = excluded.severity, detail = excluded.detail`,
				p.TenantID, findings.CloudSecurity, fp, f.Severity, fmt.Sprintf("%s account %s: %s", s.Provider, f.Account, f.Title), detail, o.project, o.env, s.now()); err != nil {
				return err
			}
		}
		return s.resolveGone(ctx, tx, findings.CloudSecurity, prefix, seen, "no longer reported by the client's cloud")
	})
}

// resolveGone resolves the open Findings of kind under prefix that the
// latest read did not report.
func (s *Sync) resolveGone(ctx context.Context, tx pgx.Tx, kind findings.Kind, prefix string, seen []string, resolution string) error {
	_, err := tx.Exec(ctx, `UPDATE findings SET status = 'resolved', resolved_at = $4, resolution = $5
		WHERE kind = $1 AND status = 'open' AND starts_with(fingerprint, $2) AND NOT (fingerprint = ANY ($3))`,
		kind, prefix, seen, s.now(), resolution)
	return err
}
