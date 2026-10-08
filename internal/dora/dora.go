// Package dora computes the five DORA metrics (2024 definitions, #148) from
// Keel's deployment records — the same rows the deployment Activities are
// written from — for production Environments:
//
//   - Deployment frequency: production deployments per day.
//   - Change lead time: Release created (built from a commit) → running in
//     production. Keel does not see the commit time, so the Release's
//     creation by CI stands in for it; median.
//   - Change fail rate: deployments later marked failed ÷ deployments.
//   - Failed deployment recovery time: failure → the next successful
//     deployment of the same Service to the same Environment; median.
//   - Rework rate: deployments requested within 24h after a failure of the
//     same Service and Environment (unplanned, to fix it) ÷ deployments.
package dora

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/store"
)

// ReworkWindow is how soon after a failure a deployment counts as rework.
const ReworkWindow = 24 * time.Hour

// Metrics for one scope and period.
type Metrics struct {
	Scope          string   `json:"scope"`
	Deployments    int      `json:"deployments"`
	PerDay         float64  `json:"deployments_per_day"`
	LeadTimeHours  *float64 `json:"lead_time_hours"`
	ChangeFailRate *float64 `json:"change_fail_rate"`
	RecoveryHours  *float64 `json:"recovery_hours"`
	ReworkRate     *float64 `json:"rework_rate"`
	Failed         int      `json:"failed"`
	Rework         int      `json:"rework"`
}

// Report is a Tenant's DORA for a period.
type Report struct {
	From     time.Time `json:"from"`
	To       time.Time `json:"to"`
	Tenant   Metrics   `json:"tenant"`
	Services []Metrics `json:"services"`
}

type deploy struct {
	service, env                        string
	requested, deployed, releaseCreated time.Time
	failed                              *time.Time
}

// Service computes metrics and records failures.
type Service struct {
	Store *store.Store
}

var ErrNotFound = errors.New("deployment not found")

// MarkFailed records that a deployment failed in production use.
func (s Service) MarkFailed(ctx context.Context, tenant, promotion, reason string, at time.Time, by activity.Actor) error {
	return s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE promotions SET failed_at = $2, failure_reason = $3 WHERE id = $1 AND state = 'deployed' AND failed_at IS NULL`, promotion, at, reason)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		_, err = activity.Record(ctx, tx, activity.Activity{TenantID: tenant, Source: "keel/dora", Type: "keel.deployment.failed", Subject: "promotion/" + promotion,
			Operation: "MarkDeploymentFailed", Kind: activity.Update, Actor: by, Outcome: activity.Failure,
			Resources: []activity.Resource{{Type: "promotion", UID: promotion}}, StatusDetail: reason, Why: activity.Why{Reason: reason}})
		return err
	})
}

// Compute returns production DORA for [from, to).
func (s Service) Compute(ctx context.Context, tenant string, from, to time.Time) (Report, error) {
	rep := Report{From: from, To: to}
	var all []deploy
	names := map[string]string{}
	err := s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		// Deployments up to 'to' (earlier ones are needed for rework/recovery context).
		rows, err := tx.Query(ctx, `SELECT s.id::text, s.slug, p.environment_id::text, p.requested_at, p.deployed_at, r.created_at, p.failed_at
			FROM promotions p JOIN releases r ON r.id = p.release_id JOIN services s ON s.id = r.service_id JOIN environments e ON e.id = p.environment_id
			WHERE p.state = 'deployed' AND p.deployed_at < $1 AND e.name IN ('prod', 'production', 'prd')
			ORDER BY p.deployed_at`, to)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var d deploy
			var slug string
			if err := rows.Scan(&d.service, &slug, &d.env, &d.requested, &d.deployed, &d.releaseCreated, &d.failed); err != nil {
				return err
			}
			names[d.service] = slug
			all = append(all, d)
		}
		return rows.Err()
	})
	if err != nil {
		return rep, err
	}
	days := to.Sub(from).Hours() / 24
	rep.Tenant = compute("tenant", all, from, to, days)
	byService := map[string][]deploy{}
	for _, d := range all {
		byService[d.service] = append(byService[d.service], d)
	}
	for svc, ds := range byService {
		m := compute(names[svc], ds, from, to, days)
		if m.Deployments > 0 {
			rep.Services = append(rep.Services, m)
		}
	}
	sort.Slice(rep.Services, func(i, j int) bool { return rep.Services[i].Scope < rep.Services[j].Scope })
	return rep, nil
}

func compute(scope string, all []deploy, from, to time.Time, days float64) Metrics {
	m := Metrics{Scope: scope}
	var leads, recoveries []float64
	for i, d := range all {
		in := !d.deployed.Before(from) && d.deployed.Before(to)
		if !in {
			continue
		}
		m.Deployments++
		leads = append(leads, d.deployed.Sub(d.releaseCreated).Hours())
		if d.failed != nil {
			m.Failed++
			// Recovery: the next deployment of the same Service to the same Environment.
			for _, n := range all[i+1:] {
				if n.service == d.service && n.env == d.env && n.deployed.After(*d.failed) {
					recoveries = append(recoveries, n.deployed.Sub(*d.failed).Hours())
					break
				}
			}
		}
		// Rework: requested shortly after an earlier failure of the same Service/Environment.
		for _, p := range all[:i] {
			if p.service == d.service && p.env == d.env && p.failed != nil && !d.requested.Before(*p.failed) && d.requested.Sub(*p.failed) <= ReworkWindow {
				m.Rework++
				break
			}
		}
	}
	if days > 0 {
		m.PerDay = round(float64(m.Deployments) / days)
	}
	if m.Deployments > 0 {
		cfr := round(float64(m.Failed) / float64(m.Deployments))
		rw := round(float64(m.Rework) / float64(m.Deployments))
		m.ChangeFailRate, m.ReworkRate = &cfr, &rw
	}
	m.LeadTimeHours = median(leads)
	m.RecoveryHours = median(recoveries)
	return m
}

func median(xs []float64) *float64 {
	if len(xs) == 0 {
		return nil
	}
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	v := s[len(s)/2]
	if len(s)%2 == 0 {
		v = (s[len(s)/2-1] + s[len(s)/2]) / 2
	}
	v = round(v)
	return &v
}

func round(f float64) float64 {
	return float64(int64(f*100+0.5)) / 100
}

// String is a one-line summary (reports, logs).
func (m Metrics) String() string {
	f := func(p *float64, unit string) string {
		if p == nil {
			return "n/a"
		}
		return fmt.Sprintf("%.2f%s", *p, unit)
	}
	return fmt.Sprintf("%d deployments (%.2f/day), lead time %s, change fail rate %s, recovery %s, rework %s",
		m.Deployments, m.PerDay, f(m.LeadTimeHours, "h"), f(m.ChangeFailRate, ""), f(m.RecoveryHours, "h"), f(m.ReworkRate, ""))
}
