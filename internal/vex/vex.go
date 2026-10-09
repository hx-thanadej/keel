// Package vex records OpenVEX statements (#111): whether a Service (or one
// Release) is affected by a vulnerability. not_affected must say why.
// not_affected and fixed statements resolve the matching Findings and stop
// scanners and OSV from raising them again; affected and
// under_investigation keep them open.
package vex

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/store"
)

var (
	ErrInvalid  = errors.New("invalid")
	ErrNotFound = errors.New("not found")
)

// Justifications are OpenVEX v0.2's.
var Justifications = map[string]bool{"component_not_present": true, "vulnerable_code_not_present": true, "vulnerable_code_not_in_execute_path": true,
	"vulnerable_code_cannot_be_controlled_by_adversary": true, "inline_mitigations_already_exist": true}

var vulnRe = regexp.MustCompile(`^(CVE-\d{4}-\d{4,}|GHSA(-[23456789cfghjmpqrvwx]{4}){3}|[A-Z]+-[A-Za-z0-9-]+)$`)

// Statement is one record.
type Statement struct {
	ID              string    `json:"id"`
	Vulnerability   string    `json:"vulnerability"`
	ServiceID       string    `json:"service_id"`
	ReleaseID       *string   `json:"release_id"`
	Status          string    `json:"status"`
	Justification   *string   `json:"justification"`
	ImpactStatement *string   `json:"impact_statement"`
	ActionStatement *string   `json:"action_statement"`
	Author          string    `json:"author"`
	CreatedAt       time.Time `json:"created_at"`
}

// Service manages statements.
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

const cols = `id::text, vulnerability, service_id::text, release_id::text, status, justification, impact_statement, action_statement, author, created_at`

// Record adds a statement.
func (s Service) Record(ctx context.Context, tenant string, in Statement, by activity.Actor) (Statement, error) {
	switch {
	case !vulnRe.MatchString(in.Vulnerability):
		return Statement{}, fmt.Errorf("%w: vulnerability must be a CVE, GHSA or OSV id", ErrInvalid)
	case in.Status != "not_affected" && in.Status != "affected" && in.Status != "fixed" && in.Status != "under_investigation":
		return Statement{}, fmt.Errorf("%w: status must be not_affected, affected, fixed or under_investigation", ErrInvalid)
	case in.Justification != nil && !Justifications[*in.Justification]:
		return Statement{}, fmt.Errorf("%w: unknown justification %q", ErrInvalid, *in.Justification)
	case in.Status == "not_affected" && in.Justification == nil && (in.ImpactStatement == nil || *in.ImpactStatement == ""):
		return Statement{}, fmt.Errorf("%w: not_affected needs a justification or an impact statement", ErrInvalid)
	case in.Status == "affected" && (in.ActionStatement == nil || *in.ActionStatement == ""):
		return Statement{}, fmt.Errorf("%w: affected needs an action statement", ErrInvalid)
	}
	var out Statement
	err := s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		var ok bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM services WHERE id = $1) AND ($2::uuid IS NULL OR EXISTS (SELECT 1 FROM releases WHERE id = $2 AND service_id = $1))`,
			in.ServiceID, in.ReleaseID).Scan(&ok); err != nil {
			return err
		}
		if !ok {
			return ErrNotFound
		}
		row := tx.QueryRow(ctx, `INSERT INTO vex_statements (tenant_id, vulnerability, service_id, release_id, status, justification, impact_statement, action_statement, author)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING `+cols, tenant, in.Vulnerability, in.ServiceID, in.ReleaseID, in.Status, in.Justification, in.ImpactStatement, in.ActionStatement, by.UID)
		var err error
		if out, err = scan(row); err != nil {
			return err
		}
		resolved := int64(0)
		if (in.Status == "not_affected" || in.Status == "fixed") && in.ReleaseID == nil {
			why := "VEX " + in.Status
			if in.Justification != nil {
				why += ": " + *in.Justification
			} else if in.ImpactStatement != nil {
				why += ": " + *in.ImpactStatement
			}
			tag, err := tx.Exec(ctx, `UPDATE findings SET status = 'resolved', resolved_at = $4, resolution = $3
				WHERE status = 'open' AND kind = 'vulnerability' AND fingerprint = 'vuln:' || $1 || ':' || $2`, in.Vulnerability, in.ServiceID, why, s.now())
			if err != nil {
				return err
			}
			resolved = tag.RowsAffected()
		}
		_, err = activity.Record(ctx, tx, activity.Activity{TenantID: tenant, Source: "keel/vex", Type: "keel.vex.recorded", Subject: "service/" + in.ServiceID,
			Operation: "RecordVEX", Kind: activity.Create, Actor: by, Outcome: activity.Success,
			Resources:    []activity.Resource{{Type: "service", UID: in.ServiceID}, {Type: "vex_statement", UID: out.ID}},
			StatusDetail: fmt.Sprintf("%s %s; %d Finding(s) resolved", in.Vulnerability, in.Status, resolved)})
		return err
	})
	return out, err
}

func scan(r pgx.Row) (Statement, error) {
	var x Statement
	err := r.Scan(&x.ID, &x.Vulnerability, &x.ServiceID, &x.ReleaseID, &x.Status, &x.Justification, &x.ImpactStatement, &x.ActionStatement, &x.Author, &x.CreatedAt)
	return x, err
}

// List returns statements for a Service (or all).
func (s Service) List(ctx context.Context, tenant, service string) ([]Statement, error) {
	var out []Statement
	err := s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+cols+` FROM vex_statements WHERE ($1 = '' OR service_id::text = $1) ORDER BY created_at DESC LIMIT 500`, service)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (Statement, error) { return scan(r) })
		return err
	})
	return out, err
}

// Document renders an OpenVEX v0.2 document for one Release: the latest
// statement per vulnerability that applies to it (Release-specific wins).
func (s Service) Document(ctx context.Context, tenant, release, author string) ([]byte, error) {
	var images []struct{ Name, Digest string }
	var stmts []Statement
	err := s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		var raw []byte
		var svc string
		err := tx.QueryRow(ctx, `SELECT images, service_id::text FROM releases WHERE id = $1`, release).Scan(&raw, &svc)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		_ = json.Unmarshal(raw, &images)
		rows, err := tx.Query(ctx, `SELECT DISTINCT ON (vulnerability) `+cols+` FROM vex_statements
			WHERE service_id = $1 AND (release_id IS NULL OR release_id = $2)
			ORDER BY vulnerability, (release_id IS NOT NULL) DESC, created_at DESC`, svc, release)
		if err != nil {
			return err
		}
		stmts, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (Statement, error) { return scan(r) })
		return err
	})
	if err != nil {
		return nil, err
	}
	var products []any
	for _, img := range images {
		products = append(products, map[string]any{"@id": "pkg:oci/" + img.Name + "@" + img.Digest})
	}
	var out []any
	for _, st := range stmts {
		m := map[string]any{"vulnerability": map[string]string{"name": st.Vulnerability}, "products": products, "status": st.Status, "timestamp": st.CreatedAt.UTC().Format(time.RFC3339)}
		if st.Justification != nil {
			m["justification"] = *st.Justification
		}
		if st.ImpactStatement != nil {
			m["impact_statement"] = *st.ImpactStatement
		}
		if st.ActionStatement != nil {
			m["action_statement"] = *st.ActionStatement
		}
		out = append(out, m)
	}
	if out == nil {
		out = []any{}
	}
	return json.MarshalIndent(map[string]any{
		"@context": "https://openvex.dev/ns/v0.2.0", "@id": "https://keel/vex/release/" + release,
		"author": author, "timestamp": time.Now().UTC().Format(time.RFC3339), "version": 1, "statements": out,
	}, "", "  ")
}
