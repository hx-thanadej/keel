// Package maturity runs the quarterly platform maturity self-assessment
// (#154): a versioned questionnaire over the CNCF model's five aspects, with
// what Keel can measure pre-filled, answers stored per quarter, a reminder
// Finding when a quarter has none, and the trend across quarters.
package maturity

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
	"go.yaml.in/yaml/v3"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/dora"
	"github.com/hx-thanadej/keel/internal/store"
)

//go:embed questionnaire.yaml
var questionnaireYAML []byte

// Aspect is one dimension and its level descriptions (index 0 = level 1).
type Aspect struct {
	ID       string   `yaml:"id" json:"id"`
	Title    string   `yaml:"title" json:"title"`
	Question string   `yaml:"question" json:"question"`
	Measured string   `yaml:"measured" json:"measured,omitempty"`
	Levels   []string `yaml:"levels" json:"levels"`
}

// Questionnaire is the versioned set of questions.
type Questionnaire struct {
	Version string   `yaml:"version" json:"version"`
	Levels  []string `yaml:"levels" json:"levels"`
	Aspects []Aspect `yaml:"aspects" json:"aspects"`
}

// Load parses the embedded questionnaire.
func Load() (Questionnaire, error) {
	var q Questionnaire
	if err := yaml.Unmarshal(questionnaireYAML, &q); err != nil {
		return q, err
	}
	if q.Version == "" || len(q.Aspects) == 0 {
		return q, errors.New("maturity: questionnaire has no version or aspects")
	}
	for _, a := range q.Aspects {
		if len(a.Levels) != len(q.Levels) {
			return q, fmt.Errorf("maturity: aspect %s has %d levels, want %d", a.ID, len(a.Levels), len(q.Levels))
		}
	}
	return q, nil
}

// Indicators are what Keel measures for the quarter so far.
type Indicators struct {
	Services         int            `json:"services"`
	TemplateAdoption *float64       `json:"template_adoption"` // share of Services created from a template
	Environments     int            `json:"environments"`
	SelfServiceEnvs  *float64       `json:"self_service_environments"` // share vended through Keel
	DORA             dora.Metrics   `json:"dora"`
	Suggested        map[string]int `json:"suggested_levels"` // aspect → level 1..4 from the measures
}

// Answer is one aspect's level and note.
type Answer struct {
	Level int    `json:"level"`
	Note  string `json:"note,omitempty"`
}

// Assessment is one quarter's submission.
type Assessment struct {
	Quarter     string            `json:"quarter"` // 2026-Q4
	Version     string            `json:"version"`
	Answers     map[string]Answer `json:"answers"`
	Indicators  Indicators        `json:"indicators"`
	SubmittedBy string            `json:"submitted_by"`
	SubmittedAt time.Time         `json:"submitted_at"`
}

// Service stores and measures assessments.
type Service struct {
	Store *store.Store
	DORA  dora.Service
	Now   func() time.Time
}

var (
	ErrInvalid = errors.New("invalid assessment")
	quarterRE  = regexp.MustCompile(`^(\d{4})-Q([1-4])$`)
	reminderBy = 60 // days into a quarter before the reminder Finding opens
	keelActor  = activity.Actor{Type: activity.ActorKeel, UID: "keel:maturity"}
)

// CurrentQuarter names the quarter on the service clock.
func (s Service) CurrentQuarter() string { return Quarter(s.now()) }

func (s Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

// Quarter names the quarter containing t.
func Quarter(t time.Time) string { return fmt.Sprintf("%d-Q%d", t.Year(), (int(t.Month())-1)/3+1) }

// QuarterStart returns the first instant of a quarter name.
func QuarterStart(q string) (time.Time, error) {
	m := quarterRE.FindStringSubmatch(q)
	if m == nil {
		return time.Time{}, fmt.Errorf("%w: quarter is YYYY-Qn", ErrInvalid)
	}
	var y, n int
	_, _ = fmt.Sscan(m[1], &y)
	_, _ = fmt.Sscan(m[2], &n)
	return time.Date(y, time.Month((n-1)*3+1), 1, 0, 0, 0, 0, time.UTC), nil
}

// Measure computes the indicators for a quarter (to now if it is current).
func (s Service) Measure(ctx context.Context, tenant, quarter string) (Indicators, error) {
	from, err := QuarterStart(quarter)
	if err != nil {
		return Indicators{}, err
	}
	to := from.AddDate(0, 3, 0)
	if n := s.now(); to.After(n) {
		to = n
	}
	var ind Indicators
	err = s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		var templated, vended int
		if err := tx.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE template <> '') FROM services WHERE archived_at IS NULL`).Scan(&ind.Services, &templated); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT count(*),
				count(*) FILTER (WHERE EXISTS (SELECT 1 FROM flows f WHERE f.kind LIKE 'vend_environment_%' AND f.state = 'succeeded' AND f.subject LIKE 'environment/' || e.id::text || '/%'))
			FROM environments e WHERE e.archived_at IS NULL`).Scan(&ind.Environments, &vended); err != nil {
			return err
		}
		ind.TemplateAdoption = share(templated, ind.Services)
		ind.SelfServiceEnvs = share(vended, ind.Environments)
		return nil
	})
	if err != nil {
		return ind, err
	}
	rep, err := s.DORA.Compute(ctx, tenant, from, to)
	if err != nil {
		return ind, err
	}
	ind.DORA = rep.Tenant
	ind.Suggested = map[string]int{}
	if ind.TemplateAdoption != nil {
		ind.Suggested["adoption"] = band(*ind.TemplateAdoption)
	}
	if ind.SelfServiceEnvs != nil {
		ind.Suggested["interfaces"] = band(*ind.SelfServiceEnvs)
	}
	// Measurement: DORA collected at all is Operational; with lead time and
	// change failure rate both known, Scalable. Optimizing is a human call.
	switch {
	case ind.DORA.LeadTimeHours != nil && ind.DORA.ChangeFailRate != nil:
		ind.Suggested["measurement"] = 3
	case ind.DORA.Deployments > 0:
		ind.Suggested["measurement"] = 2
	}
	return ind, nil
}

func share(n, of int) *float64 {
	if of == 0 {
		return nil
	}
	v := float64(n) / float64(of)
	return &v
}

// band maps a share to a level: <25% 1, <50% 2, <80% 3, else 4.
func band(v float64) int {
	switch {
	case v < 0.25:
		return 1
	case v < 0.5:
		return 2
	case v < 0.8:
		return 3
	}
	return 4
}

// Submit stores (or replaces) a quarter's answers with fresh indicators and
// resolves that quarter's reminder.
func (s Service) Submit(ctx context.Context, tenant, quarter string, answers map[string]Answer, by activity.Actor) (Assessment, error) {
	q, err := Load()
	if err != nil {
		return Assessment{}, err
	}
	start, err := QuarterStart(quarter)
	if err != nil {
		return Assessment{}, err
	}
	if start.After(s.now()) {
		return Assessment{}, fmt.Errorf("%w: %s has not started", ErrInvalid, quarter)
	}
	for _, a := range q.Aspects {
		ans, ok := answers[a.ID]
		if !ok || ans.Level < 1 || ans.Level > len(q.Levels) {
			return Assessment{}, fmt.Errorf("%w: %s needs a level 1-%d", ErrInvalid, a.ID, len(q.Levels))
		}
		if len(ans.Note) > 2000 {
			return Assessment{}, fmt.Errorf("%w: %s note is over 2000 characters", ErrInvalid, a.ID)
		}
	}
	if len(answers) != len(q.Aspects) {
		return Assessment{}, fmt.Errorf("%w: unknown aspect in answers", ErrInvalid)
	}
	ind, err := s.Measure(ctx, tenant, quarter)
	if err != nil {
		return Assessment{}, err
	}
	a := Assessment{Quarter: quarter, Version: q.Version, Answers: answers, Indicators: ind, SubmittedBy: by.UID, SubmittedAt: s.now()}
	ansJSON, _ := json.Marshal(answers)
	indJSON, _ := json.Marshal(ind)
	return a, s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO maturity_assessments (tenant_id, quarter, version, answers, indicators, submitted_by, submitted_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			ON CONFLICT (tenant_id, quarter) DO UPDATE SET version = excluded.version, answers = excluded.answers, indicators = excluded.indicators,
				submitted_by = excluded.submitted_by, submitted_at = excluded.submitted_at`,
			tenant, quarter, q.Version, ansJSON, indJSON, by.UID, a.SubmittedAt); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE findings SET status = 'resolved', resolved_at = $2, resolution = 'assessment submitted'
			WHERE kind = 'maturity_assessment_due' AND status = 'open' AND fingerprint = $1`, "maturity:"+quarter, a.SubmittedAt); err != nil {
			return err
		}
		_, err := activity.Record(ctx, tx, activity.Activity{TenantID: tenant, Source: "keel/maturity", Type: "keel.maturity.assessed",
			Subject: "tenant/" + tenant + "/maturity/" + quarter, Operation: "SubmitAssessment", Kind: activity.Update, Actor: by,
			Outcome: activity.Success, StatusDetail: fmt.Sprintf("%s %s", quarter, q.Version)})
		return err
	})
}

// List returns every stored assessment, oldest first (the trend).
func (s Service) List(ctx context.Context, tenant string) ([]Assessment, error) {
	out := []Assessment{}
	err := s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT quarter, version, answers, indicators, submitted_by, submitted_at FROM maturity_assessments ORDER BY quarter`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var a Assessment
			var ans, ind []byte
			if err := rows.Scan(&a.Quarter, &a.Version, &ans, &ind, &a.SubmittedBy, &a.SubmittedAt); err != nil {
				return err
			}
			if err := json.Unmarshal(ans, &a.Answers); err != nil {
				return err
			}
			if err := json.Unmarshal(ind, &a.Indicators); err != nil {
				return err
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	return out, err
}

// Remind opens a low Finding for every Tenant whose current quarter has no
// assessment once the quarter is reminderBy days old, due at quarter end.
func (s Service) Remind(ctx context.Context) (int, error) {
	now := s.now()
	quarter := Quarter(now)
	start, _ := QuarterStart(quarter)
	if now.Sub(start) < time.Duration(reminderBy)*24*time.Hour {
		return 0, nil
	}
	rows, err := s.Store.AppPool().Query(ctx, `SELECT t::text FROM tenant_ids() AS t`)
	if err != nil {
		return 0, err
	}
	tenants, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return 0, err
	}
	opened := 0
	for _, tenant := range tenants {
		err := s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
			tag, err := tx.Exec(ctx, `INSERT INTO findings (tenant_id, kind, fingerprint, severity, title, detail, first_seen_at)
				SELECT $1, 'maturity_assessment_due', $2, 'low', $3, $4, $6
				WHERE NOT EXISTS (SELECT 1 FROM maturity_assessments WHERE quarter = $5)
				ON CONFLICT (tenant_id, fingerprint) WHERE status = 'open' DO NOTHING`,
				tenant, "maturity:"+quarter, "Platform maturity self-assessment for "+quarter+" not done",
				fmt.Sprintf(`{"quarter": %q, "due": %q}`, quarter, start.AddDate(0, 3, 0).Format(time.RFC3339)), quarter, now)
			if err == nil {
				opened += int(tag.RowsAffected())
			}
			return err
		})
		if err != nil {
			return opened, fmt.Errorf("tenant %s: %w", tenant, err)
		}
	}
	return opened, nil
}

// SystemActor is Keel itself.
func SystemActor() activity.Actor { return keelActor }
