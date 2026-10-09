package anomaly

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/store"
)

// Runner scans every Tenant's spend for the latest complete day.
type Runner struct {
	Store  *store.Store
	Config Config
	Now    func() time.Time
}

// RunResult counts what changed.
type RunResult struct {
	Raised, Updated, Resolved int
}

const baselineDays = 28

var actor = activity.Actor{Type: activity.ActorKeel, UID: "keel:cost-anomaly"}

type group struct {
	project, env, service string
}

// Run judges yesterday (UTC) for every Project × Environment × service.
func (r *Runner) Run(ctx context.Context) (RunResult, error) {
	now := time.Now
	if r.Now != nil {
		now = r.Now
	}
	n := now().UTC()
	asOf := time.Date(n.Year(), n.Month(), n.Day(), 0, 0, 0, 0, time.UTC).AddDate(0, 0, -1)
	rows, err := r.Store.AppPool().Query(ctx, `SELECT t::text FROM tenant_ids() AS t`)
	if err != nil {
		return RunResult{}, err
	}
	tenants, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return RunResult{}, err
	}
	var res RunResult
	for _, t := range tenants {
		err := r.Store.InTenant(ctx, t, func(tx pgx.Tx) error { return r.tenant(ctx, tx, t, asOf, n, &res) })
		if err != nil {
			return res, fmt.Errorf("tenant %s: %w", t, err)
		}
	}
	return res, nil
}

func (r *Runner) tenant(ctx context.Context, tx pgx.Tx, tenant string, asOf, now time.Time, res *RunResult) error {
	from := asOf.AddDate(0, 0, -(baselineDays + 3))
	var currency string
	if err := tx.QueryRow(ctx, `SELECT currency FROM tenants WHERE id = $1`, tenant).Scan(&currency); err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `
		SELECT project_id::text, environment_id::text, service_name, d, coalesce(sum(fx_convert(amt, cur, $3, d)), 0)::float8
		FROM (SELECT project_id, coalesce(environment_id::text, '') AS environment_id, service_name, (charge_period_start AT TIME ZONE 'UTC')::date AS d,
		             billing_currency AS cur, sum(coalesce(effective_cost, billed_cost)) AS amt
		      FROM cost_facts WHERE current AND project_id IS NOT NULL AND charge_period_start >= $1 AND charge_period_start < $2
		      GROUP BY 1, 2, 3, 4, 5) x
		GROUP BY 1, 2, 3, 4`, from, asOf.AddDate(0, 0, 1), currency)
	if err != nil {
		return err
	}
	series := map[group]map[time.Time]float64{}
	for rows.Next() {
		var g group
		var d time.Time
		var v float64
		if err := rows.Scan(&g.project, &g.env, &g.service, &d, &v); err != nil {
			rows.Close()
			return err
		}
		if series[g] == nil {
			series[g] = map[time.Time]float64{}
		}
		series[g][time.Date(d.Year(), d.Month(), d.Day(), 0, 0, 0, 0, time.UTC)] = v
	}
	rows.Close()

	judge := func(g group, day time.Time) Verdict {
		hist := make([]float64, baselineDays)
		for i := range hist {
			hist[i] = series[g][day.AddDate(0, 0, -baselineDays+i)]
		}
		return Detect(hist, series[g][day], r.Config)
	}

	// Raise or refresh.
	for g := range series {
		v := judge(g, asOf)
		if !v.Anomalous {
			continue
		}
		top, err := topResources(ctx, tx, g, asOf, currency)
		if err != nil {
			return err
		}
		detail := map[string]any{
			"service": g.service, "day": asOf.Format("2006-01-02"), "currency": currency,
			"actual": money(v.Actual), "expected": money(v.Expected), "excess": money(v.Excess),
			"top_resources": top, "detected_after_hours": math.Round(now.Sub(asOf.AddDate(0, 0, 1)).Hours()*10) / 10,
		}
		title := fmt.Sprintf("%s spend %s %s on %s, expected about %s", g.service, money(v.Actual), currency, asOf.Format("2 Jan"), money(v.Expected))
		var env *string
		if g.env != "" {
			env = &g.env
		}
		var id string
		var inserted bool
		err = tx.QueryRow(ctx, `
			INSERT INTO findings (tenant_id, kind, fingerprint, severity, title, detail, project_id, environment_id, owner_team_id, first_seen_at)
			VALUES ($1, 'cost_anomaly', $2, $3, $4, $5, $6, $7, (SELECT team_id FROM projects WHERE id = $6), $9)
			ON CONFLICT (tenant_id, fingerprint) WHERE status = 'open'
			DO UPDATE SET last_seen_at = now(),
			    detail = findings.detail || jsonb_build_object('latest', excluded.detail),
			    severity = CASE WHEN array_position(ARRAY['low','medium','high','critical'], excluded.severity) > array_position(ARRAY['low','medium','high','critical'], findings.severity) THEN excluded.severity ELSE findings.severity END
			WHERE findings.detail->>'day' <> $8 AND coalesce(findings.detail->'latest'->>'day', '') <> $8
			RETURNING id::text, (xmax = 0)`,
			tenant, "cost_anomaly:"+g.project+":"+g.env+":"+g.service, v.Severity, title, detail, g.project, env, asOf.Format("2006-01-02"), now).Scan(&id, &inserted)
		if err == pgx.ErrNoRows {
			continue // already recorded for this day
		}
		if err != nil {
			return err
		}
		if !inserted {
			res.Updated++
			continue
		}
		res.Raised++
		if _, err := activity.Record(ctx, tx, activity.Activity{TenantID: tenant, Source: "keel/cost-anomaly", Type: "keel.finding.raised",
			Subject: "finding/" + id, Operation: "RaiseFinding", Kind: activity.Create, Actor: actor, Outcome: activity.Success,
			Resources: []activity.Resource{{Type: "finding", UID: id}}, StatusDetail: v.Severity + ": " + title}); err != nil {
			return err
		}
	}

	// Auto-resolve open anomalies after three normal days in a row.
	open, err := tx.Query(ctx, `SELECT id::text, fingerprint FROM findings WHERE kind = 'cost_anomaly' AND status = 'open'`)
	if err != nil {
		return err
	}
	type of struct{ id, fp string }
	var opens []of
	for open.Next() {
		var o of
		if err := open.Scan(&o.id, &o.fp); err != nil {
			open.Close()
			return err
		}
		opens = append(opens, o)
	}
	open.Close()
	for _, o := range opens {
		parts := strings.SplitN(o.fp, ":", 4) // cost_anomaly:<project>:<env>:<service>
		if len(parts) != 4 {
			continue
		}
		g := group{project: parts[1], env: parts[2], service: parts[3]}
		normal := true
		for k := 0; k < 3; k++ {
			if judge(g, asOf.AddDate(0, 0, -k)).Anomalous {
				normal = false
			}
		}
		if !normal {
			continue
		}
		if _, err := tx.Exec(ctx, `UPDATE findings SET status = 'resolved', resolved_at = $2, resolution = 'auto: spend back within baseline for 3 days' WHERE id = $1`, o.id, now); err != nil {
			return err
		}
		res.Resolved++
		if _, err := activity.Record(ctx, tx, activity.Activity{TenantID: tenant, Source: "keel/cost-anomaly", Type: "keel.finding.resolved",
			Subject: "finding/" + o.id, Operation: "ResolveFinding", Kind: activity.Update, Actor: actor, Outcome: activity.Success,
			Resources: []activity.Resource{{Type: "finding", UID: o.id}}, StatusDetail: "auto: spend back within baseline for 3 days"}); err != nil {
			return err
		}
	}
	return nil
}

// topResources ranks resources by how far the day's spend exceeds their own
// baseline median.
func topResources(ctx context.Context, tx pgx.Tx, g group, day time.Time, currency string) ([]map[string]string, error) {
	rows, err := tx.Query(ctx, `
		SELECT resource_id, d, coalesce(sum(fx_convert(amt, cur, $6, d)), 0)::float8
		FROM (SELECT resource_id, (charge_period_start AT TIME ZONE 'UTC')::date AS d, billing_currency AS cur, sum(coalesce(effective_cost, billed_cost)) AS amt
		      FROM cost_facts WHERE current AND project_id::text = $1 AND coalesce(environment_id::text, '') = $2 AND service_name = $3
		        AND charge_period_start >= $4 AND charge_period_start < $5
		      GROUP BY 1, 2, 3) x
		GROUP BY 1, 2`, g.project, g.env, g.service, day.AddDate(0, 0, -baselineDays), day.AddDate(0, 0, 1), currency)
	if err != nil {
		return nil, err
	}
	byRes := map[string]map[time.Time]float64{}
	for rows.Next() {
		var res string
		var d time.Time
		var v float64
		if err := rows.Scan(&res, &d, &v); err != nil {
			rows.Close()
			return nil, err
		}
		if byRes[res] == nil {
			byRes[res] = map[time.Time]float64{}
		}
		byRes[res][time.Date(d.Year(), d.Month(), d.Day(), 0, 0, 0, 0, time.UTC)] = v
	}
	rows.Close()
	type delta struct {
		res       string
		today, dl float64
	}
	var ds []delta
	for res, s := range byRes {
		hist := make([]float64, baselineDays)
		for i := range hist {
			hist[i] = s[day.AddDate(0, 0, -baselineDays+i)]
		}
		d := delta{res: res, today: s[day]}
		d.dl = d.today - median(hist)
		if d.dl > 0 {
			ds = append(ds, d)
		}
	}
	sort.Slice(ds, func(i, j int) bool { return ds[i].dl > ds[j].dl })
	var out []map[string]string
	for i := 0; i < len(ds) && i < 5; i++ {
		out = append(out, map[string]string{"resource_id": ds[i].res, "actual": money(ds[i].today), "delta": money(ds[i].dl)})
	}
	return out, nil
}

func money(v float64) string { return strconv.FormatFloat(v, 'f', 2, 64) }
