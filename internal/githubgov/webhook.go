package githubgov

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/findings"
	"github.com/hx-thanadej/keel/internal/store"
)

var (
	ErrReplay     = errors.New("delivery already processed")
	ErrForeignOrg = errors.New("event from an organisation Keel does not govern")
)

// governed are the organisation webhook events that change governance (#193).
var governed = map[string]bool{
	"repository_ruleset": true, "branch_protection_rule": true, "branch_protection_configuration": true,
	"security_and_analysis": true, "repository": true, "public": true,
	"member": true, "membership": true, "team": true, "organization": true,
}

// Governs reports whether Receiver handles the webhook event.
func Governs(event string) bool { return governed[event] }

// Receiver records governance changes GitHub reports by organisation webhook
// on Free and Team, where the audit-log API is unavailable. Each delivery
// becomes one Activity in the Tenant that owns the repository. A change that
// weakens a protection the Policy owns also raises the Finding the reconciler
// would, under the same fingerprint, so the next reconcile keeps or resolves it.
type Receiver struct {
	Store  *store.Store
	Owner  string // the governed organisation, as the reconciler's Login
	Policy Policy
	Now    func() time.Time // defaults to time.Now
}

type securitySettings map[string]struct {
	Status string `json:"status"`
}

type webhookEvent struct {
	Action       string `json:"action"`
	Organization *struct {
		Login string `json:"login"`
	} `json:"organization"`
	Sender struct {
		Login string `json:"login"`
		Type  string `json:"type"`
	} `json:"sender"`
	Repository *struct {
		Name             string           `json:"name"`
		FullName         string           `json:"full_name"`
		CustomProperties map[string]any   `json:"custom_properties"`
		Security         securitySettings `json:"security_and_analysis"`
	} `json:"repository"`
	Ruleset *struct {
		Ruleset
		SourceType string `json:"source_type"`
	} `json:"repository_ruleset"`
	Changes struct {
		From struct {
			Security securitySettings `json:"security_and_analysis"`
		} `json:"from"`
	} `json:"changes"`
}

// Receive records one verified delivery. The delivery id's primary key makes
// a redelivery return ErrReplay without writing anything.
func (r Receiver) Receive(ctx context.Context, delivery, event string, body []byte) error {
	var e webhookEvent
	if err := json.Unmarshal(body, &e); err != nil {
		return fmt.Errorf("github %s payload: %w", event, err)
	}
	if e.Organization == nil || !strings.EqualFold(e.Organization.Login, r.Owner) {
		return ErrForeignOrg
	}
	slug, repo := "", ""
	if e.Repository != nil {
		repo = e.Repository.Name
		slug, _ = e.Repository.CustomProperties[PropTenant].(string)
	}
	tenant, err := tenantFor(ctx, r.Store, slug)
	if err != nil {
		return err
	}
	weak, weakened := r.weakening(event, repo, e)
	now := time.Now()
	if r.Now != nil {
		now = r.Now()
	}
	return r.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `INSERT INTO webhook_deliveries (tenant_id, source, delivery_id, event) VALUES ($1, 'github', $2, $3) ON CONFLICT DO NOTHING`, tenant, delivery, event)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrReplay
		}
		typ, op := "github."+event, event
		if e.Action != "" {
			typ, op = typ+"."+e.Action, op+"."+e.Action
		}
		subject, resource := "github/"+r.Owner, activity.Resource{Type: "github_owner", UID: r.Owner}
		if e.Repository != nil {
			subject, resource = "github/"+e.Repository.FullName, activity.Resource{Type: "github_repository", UID: e.Repository.FullName}
		}
		actor := activity.Actor{Type: activity.ActorHuman, UID: "github:" + e.Sender.Login}
		if e.Sender.Type == "Bot" {
			actor.Type = activity.ActorWorkload
		}
		detail := "delivery " + delivery
		if weakened {
			detail += "; weakens " + weak.Setting + ": " + weak.Problem
		}
		if _, err := activity.Record(ctx, tx, activity.Activity{TenantID: tenant, Source: "github/org-webhook", Type: typ, Subject: subject,
			Operation: op, Kind: kindOf(e.Action), Actor: actor, Outcome: activity.Success, Resources: []activity.Resource{resource},
			StatusDetail: detail, Time: now}); err != nil {
			return err
		}
		if !weakened {
			return nil
		}
		weak.Tenant = slug
		fp := "github:" + r.Owner + ":" + weak.Repo + ":" + weak.Setting
		item, _ := json.Marshal(weak)
		_, err = tx.Exec(ctx, `INSERT INTO findings (tenant_id, kind, fingerprint, severity, title, detail, first_seen_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			ON CONFLICT (tenant_id, fingerprint) WHERE status = 'open' DO UPDATE SET last_seen_at = now(), detail = excluded.detail`,
			tenant, findings.GitHubGovernance, fp, weak.Severity, fmt.Sprintf("GitHub %s: %s", orDefault(weak.Repo, r.Owner), weak.Problem), item, now)
		return err
	})
}

// weakening decides whether an event weakens a protection the Policy owns:
// a ruleset named in the Policy is deleted, or no longer Covers the Policy's
// ruleset; or secret scanning or push protection goes from enabled to not
// enabled. Classic branch protection, visibility and membership are not
// protections Keel owns, so they are recorded as Activities only.
func (r Receiver) weakening(event, repo string, e webhookEvent) (Item, bool) {
	by := " by @" + e.Sender.Login
	switch event {
	case "repository_ruleset":
		if e.Ruleset == nil {
			return Item{}, false
		}
		for _, s := range r.Policy.Rulesets {
			if s.Name != e.Ruleset.Name {
				continue
			}
			org := e.Ruleset.SourceType == "Organization"
			it := Item{Repo: repo, Setting: "ruleset:" + s.Name, Severity: "high"}
			if org {
				it.Repo = "" // the reconciler's fingerprint for an organisation ruleset
			}
			switch {
			case e.Action == "deleted":
				it.Problem = "ruleset deleted" + by
			case !Covers(e.Ruleset.Ruleset, s.Build(org)):
				it.Problem = "ruleset weakened" + by
			default:
				return Item{}, false
			}
			return it, true
		}
	case "security_and_analysis":
		if e.Repository == nil {
			return Item{}, false
		}
		var off []string
		for _, f := range [][2]string{{"secret_scanning", "secret scanning"}, {"secret_scanning_push_protection", "push protection"}} {
			if e.Changes.From.Security[f[0]].Status == "enabled" && e.Repository.Security[f[0]].Status != "enabled" {
				off = append(off, f[1])
			}
		}
		if len(off) > 0 {
			return Item{Repo: repo, Setting: "secret_scanning", Problem: strings.Join(off, " and ") + " turned off" + by, Severity: "high"}, true
		}
	}
	return Item{}, false
}

func kindOf(action string) activity.Kind {
	switch action {
	case "created", "added", "member_added", "member_invited":
		return activity.Create
	case "deleted", "removed", "member_removed":
		return activity.Delete
	}
	return activity.Update
}

// tenantFor is the Tenant a repository's keel-tenant slug names, or the home
// Tenant when the slug is empty or names no Tenant.
func tenantFor(ctx context.Context, s *store.Store, slug string) (string, error) {
	var id *string
	if slug != "" {
		if err := s.AppPool().QueryRow(ctx, `SELECT tenant_id_by_slug($1)::text`, slug).Scan(&id); err != nil {
			return "", err
		}
	}
	if id == nil {
		if err := s.AppPool().QueryRow(ctx, `SELECT home_tenant_id()::text`).Scan(&id); err != nil {
			return "", err
		}
	}
	if id == nil {
		return "", errors.New("no home tenant")
	}
	return *id, nil
}
