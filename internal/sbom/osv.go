package sbom

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/scans"
)

// Vuln is an OSV advisory.
type Vuln struct {
	ID       string   `json:"id"`
	Summary  string   `json:"summary"`
	Aliases  []string `json:"aliases"`
	Severity string   `json:"-"` // critical | high | medium | low
}

// OSV is the advisory database.
type OSV interface {
	// Query returns advisory ids per purl (same order as purls).
	Query(ctx context.Context, purls []string) ([][]string, error)
	Vuln(ctx context.Context, id string) (Vuln, error)
}

// OSVClient talks to api.osv.dev.
type OSVClient struct {
	BaseURL string // default https://api.osv.dev
	HTTP    *http.Client
}

func (c OSVClient) base() string {
	if c.BaseURL == "" {
		return "https://api.osv.dev"
	}
	return strings.TrimSuffix(c.BaseURL, "/")
}

func (c OSVClient) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base()+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	h := c.HTTP
	if h == nil {
		h = &http.Client{Timeout: time.Minute}
	}
	res, err := h.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = res.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 64<<20))
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("osv %s: HTTP %d: %.200s", path, res.StatusCode, raw)
	}
	return json.Unmarshal(raw, out)
}

// Query implements OSV, 1000 purls per batch.
func (c OSVClient) Query(ctx context.Context, purls []string) ([][]string, error) {
	out := make([][]string, 0, len(purls))
	for i := 0; i < len(purls); i += 1000 {
		batch := purls[i:min(i+1000, len(purls))]
		var qs []any
		for _, p := range batch {
			qs = append(qs, map[string]any{"package": map[string]string{"purl": p}})
		}
		var res struct {
			Results []struct {
				Vulns []struct {
					ID string `json:"id"`
				} `json:"vulns"`
			} `json:"results"`
		}
		if err := c.do(ctx, http.MethodPost, "/v1/querybatch", map[string]any{"queries": qs}, &res); err != nil {
			return nil, err
		}
		for j := range batch {
			var ids []string
			if j < len(res.Results) {
				for _, v := range res.Results[j].Vulns {
					ids = append(ids, v.ID)
				}
			}
			out = append(out, ids)
		}
	}
	return out, nil
}

// Vuln implements OSV.
func (c OSVClient) Vuln(ctx context.Context, id string) (Vuln, error) {
	var raw struct {
		Vuln
		DB struct {
			Severity string `json:"severity"`
		} `json:"database_specific"`
	}
	if err := c.do(ctx, http.MethodGet, "/v1/vulns/"+id, nil, &raw); err != nil {
		return Vuln{}, err
	}
	v := raw.Vuln
	switch strings.ToUpper(raw.DB.Severity) {
	case "CRITICAL":
		v.Severity = "critical"
	case "HIGH":
		v.Severity = "high"
	case "LOW":
		v.Severity = "low"
	default:
		v.Severity = "medium"
	}
	return v, nil
}

// Matcher re-matches deployed components against OSV.
type Matcher struct {
	Store interface {
		InTenant(ctx context.Context, tenant string, fn func(pgx.Tx) error) error
	}
	Tenants func(ctx context.Context) ([]string, error)
	OSV     OSV
}

// MatchResult counts what a run found.
type MatchResult struct {
	Components int `json:"components"`
	Raised     int `json:"raised"`
	Resolved   int `json:"resolved"`
}

type deployed struct {
	service, slug, project, team, purl, env, release string
}

var keelActor = activity.Actor{Type: activity.ActorKeel, UID: "keel:osv"}

// Run matches every Tenant's currently deployed Releases.
func (m Matcher) Run(ctx context.Context) (MatchResult, error) {
	var res MatchResult
	tenants, err := m.Tenants(ctx)
	if err != nil {
		return res, err
	}
	cache := map[string]Vuln{}
	for _, tenant := range tenants {
		var rows []deployed
		if err := m.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
			// The Release running in each Environment is its latest deployed promotion.
			r, err := tx.Query(ctx, `WITH current AS (
					SELECT DISTINCT ON (r.service_id, p.environment_id) r.id, r.service_id, e.name AS env
					FROM promotions p JOIN releases r ON r.id = p.release_id JOIN environments e ON e.id = p.environment_id
					WHERE p.state = 'deployed' ORDER BY r.service_id, p.environment_id, p.deployed_at DESC)
				SELECT s.id::text, s.slug, s.project_id::text, s.team_id::text, c.purl, cur.env, cur.id::text
				FROM current cur JOIN services s ON s.id = cur.service_id JOIN release_components c ON c.release_id = cur.id`)
			if err != nil {
				return err
			}
			rows, err = pgx.CollectRows(r, func(x pgx.CollectableRow) (deployed, error) {
				var d deployed
				err := x.Scan(&d.service, &d.slug, &d.project, &d.team, &d.purl, &d.env, &d.release)
				return d, err
			})
			return err
		}); err != nil {
			return res, err
		}
		if len(rows) == 0 {
			continue
		}
		var purls []string
		seen := map[string]bool{}
		services := map[string]deployed{}
		for _, d := range rows {
			services[d.service] = d
			if !seen[d.purl] {
				seen[d.purl] = true
				purls = append(purls, d.purl)
			}
		}
		res.Components += len(purls)
		ids, err := m.OSV.Query(ctx, purls)
		if err != nil {
			return res, err
		}
		vulnsOf := map[string][]string{}
		for i, p := range purls {
			vulnsOf[p] = ids[i]
		}
		type hit struct {
			v     Vuln
			d     deployed
			purls map[string]bool
			envs  map[string]bool
		}
		hits := map[string]*hit{} // fingerprint → hit
		for _, d := range rows {
			for _, id := range vulnsOf[d.purl] {
				v, ok := cache[id]
				if !ok {
					if v, err = m.OSV.Vuln(ctx, id); err != nil {
						return res, err
					}
					cache[id] = v
				}
				fp := "vuln:" + preferredID(v) + ":" + d.service
				h := hits[fp]
				if h == nil {
					h = &hit{v: v, d: d, purls: map[string]bool{}, envs: map[string]bool{}}
					hits[fp] = h
				}
				h.purls[d.purl], h.envs[d.env] = true, true
			}
		}
		err = m.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
			current := map[string][]string{}
			for fp, h := range hits {
				current[h.d.service] = append(current[h.d.service], fp)
				var suppressed bool
				if err := tx.QueryRow(ctx, `SELECT vex_suppressed($1, $2)`, preferredID(h.v), h.d.service).Scan(&suppressed); err != nil {
					return err
				}
				if suppressed {
					continue
				}
				detail, _ := json.Marshal(map[string]any{"tools": []string{"osv"}, "osv_id": h.v.ID, "aliases": h.v.Aliases, "components": keys(h.purls), "environments": keys(h.envs), "service": h.d.slug})
				title := fmt.Sprintf("%s in %s: %s", preferredID(h.v), h.d.slug, h.v.Summary)
				var inserted bool
				if err := tx.QueryRow(ctx, `INSERT INTO findings (tenant_id, kind, fingerprint, severity, title, detail, project_id, owner_team_id, service_id)
					VALUES ($1, 'vulnerability', $2, $3, $4, $5, $6, $7, $8)
					ON CONFLICT (tenant_id, fingerprint) WHERE status = 'open' DO UPDATE SET last_seen_at = now(),
					    detail = findings.detail || jsonb_build_object(
					        'tools', (SELECT jsonb_agg(DISTINCT t) FROM jsonb_array_elements(coalesce(findings.detail->'tools', '[]') || (excluded.detail->'tools')) AS t),
					        'components', excluded.detail->'components', 'environments', excluded.detail->'environments', 'osv_id', excluded.detail->'osv_id')
					RETURNING (xmax = 0)`, tenant, fp, h.v.Severity, title, detail, h.d.project, h.d.team, h.d.service).Scan(&inserted); err != nil {
					return err
				}
				if inserted {
					res.Raised++
				}
			}
			for svc := range services {
				n, err := scans.ResolveAbsent(ctx, tx, svc, "osv", current[svc])
				if err != nil {
					return err
				}
				res.Resolved += n
			}
			_, err := activity.Record(ctx, tx, activity.Activity{TenantID: tenant, Source: "keel/osv", Type: "keel.osv.matched", Subject: "tenant/" + tenant,
				Operation: "MatchOSV", Kind: activity.Read, Actor: keelActor, Outcome: activity.Success,
				StatusDetail: fmt.Sprintf("%d deployed components, %d advisories", len(purls), len(hits))})
			return err
		})
		if err != nil {
			return res, err
		}
	}
	return res, nil
}

// preferredID uses the CVE alias when there is one, so scanners reporting
// the CVE and OSV reporting the GHSA land on the same Finding.
func preferredID(v Vuln) string {
	for _, a := range v.Aliases {
		if strings.HasPrefix(a, "CVE-") {
			return a
		}
	}
	return v.ID
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
