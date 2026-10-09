package evidence

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/store"
)

// KEV lists actively exploited vulnerabilities (CISA KEV catalog).
type KEV interface {
	Exploited(ctx context.Context) (map[string]bool, error)
}

// CISAKEV fetches CISA's catalog.
type CISAKEV struct {
	URL  string // default CISA's JSON feed
	HTTP *http.Client
}

// Exploited implements KEV.
func (c CISAKEV) Exploited(ctx context.Context) (map[string]bool, error) {
	u := c.URL
	if u == "" {
		u = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	h := c.HTTP
	if h == nil {
		h = &http.Client{Timeout: time.Minute}
	}
	res, err := h.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("kev: HTTP %d", res.StatusCode)
	}
	var doc struct {
		Vulnerabilities []struct {
			CVE string `json:"cveID"`
		} `json:"vulnerabilities"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 64<<20)).Decode(&doc); err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, v := range doc.Vulnerabilities {
		out[v.CVE] = true
	}
	return out, nil
}

// CRA deadlines from becoming aware of an actively exploited vulnerability
// in a product with digital elements (Regulation (EU) 2024/2847, Art. 14).
var (
	EarlyWarning = 24 * time.Hour
	Notification = 72 * time.Hour
	FinalReport  = 14 * 24 * time.Hour
)

// CRA runs the reporting clock.
type CRA struct {
	Store *store.Store
	KEV   KEV
	Now   func() time.Time
}

var craActor = activity.Actor{Type: activity.ActorKeel, UID: "keel:cra"}

// Run raises a CRA Finding for every exploited vulnerability that affects a
// deployed Service, once, with the three deadlines from first awareness.
func (c CRA) Run(ctx context.Context) (int, error) {
	exploited, err := c.KEV.Exploited(ctx)
	if err != nil {
		return 0, err
	}
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	rows, err := c.Store.AppPool().Query(ctx, `SELECT t::text FROM tenant_ids() AS t`)
	if err != nil {
		return 0, err
	}
	tenants, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return 0, err
	}
	raised := 0
	for _, tenant := range tenants {
		err := c.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
			rows, err := tx.Query(ctx, `SELECT f.fingerprint, f.service_id::text, s.slug, f.project_id::text, s.team_id::text FROM findings f JOIN services s ON s.id = f.service_id
				WHERE f.status = 'open' AND f.kind = 'vulnerability' AND f.fingerprint LIKE 'vuln:CVE-%'
				  AND EXISTS (SELECT 1 FROM promotions p JOIN releases r ON r.id = p.release_id WHERE r.service_id = f.service_id AND p.state = 'deployed')`)
			if err != nil {
				return err
			}
			type hit struct {
				cve, service, slug, team string
				project                  *string
			}
			var hits []hit
			for rows.Next() {
				var fp string
				var h hit
				if err := rows.Scan(&fp, &h.service, &h.slug, &h.project, &h.team); err != nil {
					return err
				}
				parts := strings.Split(fp, ":")
				if len(parts) >= 2 && exploited[parts[1]] {
					h.cve = parts[1]
					hits = append(hits, h)
				}
			}
			if err := rows.Err(); err != nil {
				return err
			}
			for _, h := range hits {
				aware := now().UTC()
				detail, _ := json.Marshal(map[string]any{"cve": h.cve, "service": h.slug, "aware_at": aware,
					"early_warning_by": aware.Add(EarlyWarning), "notification_by": aware.Add(Notification), "final_report_by": aware.Add(FinalReport),
					"regulation": "EU 2024/2847 Art. 14", "source": "CISA KEV"})
				tag, err := tx.Exec(ctx, `INSERT INTO findings (tenant_id, kind, fingerprint, severity, title, detail, project_id, service_id, owner_team_id, first_seen_at)
					SELECT $1, 'cra_report', $2, 'critical', $3, $4, $5, $6, $7, $8
					WHERE NOT EXISTS (SELECT 1 FROM findings WHERE fingerprint = $2)`,
					tenant, "cra:"+h.cve+":"+h.service,
					fmt.Sprintf("CRA: %s is actively exploited and runs in %s — early warning to the CSIRT/ENISA by %s", h.cve, h.slug, aware.Add(EarlyWarning).Format("2 Jan 15:04 MST")),
					detail, h.project, h.service, h.team, aware)
				if err != nil {
					return err
				}
				if tag.RowsAffected() == 0 {
					continue // the clock started earlier
				}
				raised++
				if _, err := activity.Record(ctx, tx, activity.Activity{TenantID: tenant, Source: "keel/cra", Type: "keel.cra.clock_started", Subject: "service/" + h.service,
					Operation: "StartCRAClock", Kind: activity.Create, Actor: craActor, Outcome: activity.Success,
					StatusDetail: fmt.Sprintf("%s in %s: 24h/72h/14d from %s", h.cve, h.slug, aware.Format(time.RFC3339))}); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			return raised, err
		}
	}
	return raised, nil
}
