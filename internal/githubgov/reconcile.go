package githubgov

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/store"
)

// Item is one difference from the desired state.
type Item struct {
	Repo     string `json:"repo,omitempty"` // "" = organisation level
	Setting  string `json:"setting"`
	Problem  string `json:"problem"`
	Severity string `json:"severity"`
	Tenant   string `json:"tenant,omitempty"` // keel-tenant property of the repo
	Fixable  bool   `json:"fixable"`
	Fixed    bool   `json:"fixed"`
}

// Report is what a reconcile found and did.
type Report struct {
	Owner   string `json:"owner"`
	Plan    string `json:"plan"`
	Mode    string `json:"mode"` // org-rulesets | repo-rulesets
	Version string `json:"version"`
	Repos   int    `json:"repos"`
	Items   []Item `json:"items"`
}

// Reconciler compares GitHub with the Policy.
type Reconciler struct {
	Store     *store.Store
	API       API
	Policy    Policy
	Remediate bool
	Now       func() time.Time // defaults to time.Now
}

func (r Reconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// orgRulesetPlans can use organisation rulesets on private repositories.
func orgRulesets(org bool, plan string) bool {
	return org && plan != "free" && plan != "user"
}

// Run reconciles once and records Findings.
func (r Reconciler) Run(ctx context.Context) (Report, error) {
	owner, org := r.API.Owner()
	rep := Report{Owner: owner, Version: r.Policy.Version}
	plan, err := r.API.Plan(ctx)
	if err != nil {
		return rep, fmt.Errorf("plan: %w", err)
	}
	rep.Plan, rep.Mode = plan, "repo-rulesets"
	useOrg := orgRulesets(org, plan)
	if useOrg {
		rep.Mode = "org-rulesets"
	}
	add := func(it Item) func() {
		rep.Items = append(rep.Items, it)
		i := len(rep.Items) - 1
		return func() { rep.Items[i].Fixed = true } // an index, not a pointer: appends reallocate
	}
	note := func(problem string) { rep.Items[len(rep.Items)-1].Problem += problem }

	if org {
		if err := r.properties(ctx, add); err != nil {
			return rep, err
		}
		if err := r.subject(ctx, add); err != nil {
			return rep, err
		}
		if err := r.actions(ctx, add); err != nil {
			return rep, err
		}
	}
	if useOrg {
		have, err := r.API.OrgRulesets(ctx)
		if err != nil {
			return rep, fmt.Errorf("org rulesets: %w", err)
		}
		for _, s := range r.Policy.Rulesets {
			if err := r.ruleset(ctx, "", have, s.Build(true), add, func(rs Ruleset) error { return r.API.PutOrgRuleset(ctx, rs) }); err != nil {
				return rep, err
			}
		}
	}
	repos, err := r.API.Repos(ctx)
	if err != nil {
		return rep, fmt.Errorf("repos: %w", err)
	}
	for _, repo := range repos {
		if repo.Archived {
			continue
		}
		rep.Repos++
		tenant := repo.Properties[PropTenant]
		if org {
			var missing []string
			for _, p := range []string{PropTenant, PropProject, PropTier} {
				if repo.Properties[p] == "" {
					missing = append(missing, p)
				}
			}
			if len(missing) > 0 {
				add(Item{Repo: repo.Name, Setting: "properties", Problem: "missing " + strings.Join(missing, ", "), Severity: "medium", Tenant: tenant})
			}
		}
		if !useOrg {
			if repo.Private {
				add(Item{Repo: repo.Name, Setting: "rulesets", Problem: fmt.Sprintf("plan %q cannot enforce rulesets on private repositories", plan), Severity: "high", Tenant: tenant})
			} else {
				have, err := r.API.RepoRulesets(ctx, repo.Name)
				if err != nil {
					return rep, fmt.Errorf("rulesets %s: %w", repo.Name, err)
				}
				// Without properties, tiered rulesets cannot target; the base one applies to all.
				if err := r.ruleset(ctx, repo.Name, have, r.Policy.Rulesets[0].Build(false), add, func(rs Ruleset) error { return r.API.PutRepoRuleset(ctx, repo.Name, rs) }); err != nil {
					return rep, err
				}
				rep.Items = tag(rep.Items, repo.Name, tenant)
			}
		}
		if !repo.SecretScanning || !repo.PushProtection {
			// Public repositories get secret scanning free; private ones need GitHub Secret Protection.
			fixable := !repo.Private || useOrg
			fixed := add(Item{Repo: repo.Name, Setting: "secret_scanning", Problem: "secret scanning or push protection is off", Severity: "high", Tenant: tenant, Fixable: fixable})
			if r.Remediate && fixable {
				if err := r.API.EnableSecretScanning(ctx, repo.Name); err == nil {
					fixed()
				} else {
					note(" (enabling failed: " + err.Error() + ")")
				}
			}
		}
	}
	return rep, r.record(ctx, rep)
}

func tag(items []Item, repo, tenant string) []Item {
	for i := range items {
		if items[i].Repo == repo && items[i].Tenant == "" {
			items[i].Tenant = tenant
		}
	}
	return items
}

func (r Reconciler) properties(ctx context.Context, add func(Item) func()) error {
	have, err := r.API.PropertySchema(ctx)
	if err != nil {
		return fmt.Errorf("property schema: %w", err)
	}
	byName := map[string]Property{}
	for _, p := range have {
		byName[p.Name] = p
	}
	var drift []func()
	for _, want := range r.Policy.Properties {
		h, ok := byName[want.Name]
		switch {
		case !ok:
			drift = append(drift, add(Item{Setting: "property:" + want.Name, Problem: "custom property missing", Severity: "medium", Fixable: true}))
		case h.ValueType != want.ValueType || !sameSet(h.AllowedValues, want.AllowedValues):
			drift = append(drift, add(Item{Setting: "property:" + want.Name, Problem: "custom property definition changed", Severity: "medium", Fixable: true}))
		}
	}
	if len(drift) > 0 && r.Remediate {
		if err := r.API.PutPropertySchema(ctx, r.Policy.Properties); err != nil {
			return fmt.Errorf("put property schema: %w", err)
		}
		for _, fixed := range drift {
			fixed()
		}
	}
	return nil
}

func (r Reconciler) subject(ctx context.Context, add func(Item) func()) error {
	have, err := r.API.SubClaimKeys(ctx)
	if err != nil {
		return fmt.Errorf("oidc subject template: %w", err)
	}
	if slices.Equal(have, r.Policy.SubClaimKeys) {
		return nil
	}
	fixed := add(Item{Setting: "oidc_subject_template", Problem: fmt.Sprintf("OIDC subject claims are %v, want %v (keyless CI roles will not match)", have, r.Policy.SubClaimKeys), Severity: "high", Fixable: true})
	if r.Remediate {
		if err := r.API.PutSubClaimKeys(ctx, r.Policy.SubClaimKeys); err != nil {
			return fmt.Errorf("put oidc subject template: %w", err)
		}
		fixed()
	}
	return nil
}

// desiredActions turns the policy into GitHub's settings.
func (p ActionsPolicy) desired() ActionsSettings {
	perm := "write"
	if p.DefaultTokenRead {
		perm = "read"
	}
	return ActionsSettings{AllowedActions: "selected", SHAPinningRequired: p.SHAPinningRequired, GitHubOwnedAllowed: true, VerifiedAllowed: true,
		Patterns: p.AllowedPatterns, DefaultPermissions: perm, CanApprovePullRequests: p.CanApprovePullRequests, ForkApproval: p.ForkApproval}
}

func (r Reconciler) actions(ctx context.Context, add func(Item) func()) error {
	have, err := r.API.Actions(ctx)
	if err != nil {
		return fmt.Errorf("actions settings: %w", err)
	}
	want := r.Policy.Actions.desired()
	var problems []string
	if want.SHAPinningRequired && !have.SHAPinningRequired {
		problems = append(problems, "actions are not required to be pinned to a full commit SHA")
	}
	if have.AllowedActions != "selected" || !have.GitHubOwnedAllowed || !have.VerifiedAllowed || !sameSet(have.Patterns, want.Patterns) {
		problems = append(problems, fmt.Sprintf("allowed actions are %q %v, want GitHub-owned, verified creators and %v", have.AllowedActions, have.Patterns, want.Patterns))
	}
	if have.DefaultPermissions != want.DefaultPermissions {
		problems = append(problems, "default GITHUB_TOKEN permission is "+have.DefaultPermissions+", want "+want.DefaultPermissions)
	}
	if have.CanApprovePullRequests && !want.CanApprovePullRequests {
		problems = append(problems, "workflows may approve pull requests")
	}
	if want.ForkApproval != "" && have.ForkApproval != want.ForkApproval {
		problems = append(problems, "fork pull request workflows need approval for "+want.ForkApproval+", currently "+orDefault(have.ForkApproval, "unset"))
	}
	if len(problems) == 0 {
		return nil
	}
	fixed := add(Item{Setting: "actions", Problem: strings.Join(problems, "; "), Severity: "high", Fixable: true})
	if r.Remediate {
		if err := r.API.PutActions(ctx, want); err != nil {
			return fmt.Errorf("put actions settings: %w", err)
		}
		fixed()
	}
	return nil
}

func (r Reconciler) ruleset(_ context.Context, repo string, have []Ruleset, want Ruleset, add func(Item) func(), put func(Ruleset) error) error {
	var cur *Ruleset
	for i := range have {
		if have[i].Name == want.Name {
			cur = &have[i]
		}
	}
	problem := ""
	switch {
	case cur == nil:
		problem = "ruleset missing"
	case !Same(*cur, want):
		problem = "ruleset weakened or changed"
	default:
		return nil
	}
	fixed := add(Item{Repo: repo, Setting: "ruleset:" + want.Name, Problem: problem, Severity: "high", Fixable: true})
	if r.Remediate {
		if cur != nil {
			want.ID = cur.ID
		}
		if err := put(want); err != nil {
			return fmt.Errorf("put ruleset %s: %w", want.Name, err)
		}
		fixed()
	}
	return nil
}

func sameSet(a, b []string) bool {
	x, y := slices.Clone(a), slices.Clone(b)
	sort.Strings(x)
	sort.Strings(y)
	return slices.Equal(x, y)
}

var keelActor = activity.Actor{Type: activity.ActorKeel, UID: "keel:github-governance"}

// record writes Findings per Tenant (by the repo's keel-tenant property;
// organisation-level and unowned items go to the home Tenant) and resolves
// the ones no longer present.
func (r Reconciler) record(ctx context.Context, rep Report) error {
	var home *string
	if err := r.Store.AppPool().QueryRow(ctx, `SELECT home_tenant_id()::text`).Scan(&home); err != nil {
		return err
	}
	if home == nil {
		return fmt.Errorf("no home tenant")
	}
	byTenant := map[string][]Item{*home: nil}
	for _, it := range rep.Items {
		t := *home
		if it.Tenant != "" {
			var id *string
			if err := r.Store.AppPool().QueryRow(ctx, `SELECT tenant_id_by_slug($1)::text`, it.Tenant).Scan(&id); err != nil {
				return err
			}
			if id != nil {
				t = *id
			}
		}
		byTenant[t] = append(byTenant[t], it)
	}
	// Tenants that may hold Findings from earlier runs.
	rows, err := r.Store.AppPool().Query(ctx, `SELECT t::text FROM tenant_ids() AS t`)
	if err != nil {
		return err
	}
	all, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	prefix := "github:" + rep.Owner + ":"
	now := r.now()
	for _, tenant := range all {
		items := byTenant[tenant]
		err := r.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
			open := map[string]bool{}
			for _, it := range items {
				fp := prefix + it.Repo + ":" + it.Setting
				detail, _ := json.Marshal(it)
				title := fmt.Sprintf("GitHub %s: %s", orDefault(it.Repo, rep.Owner), it.Problem)
				if it.Fixed {
					// Restored now: record the drift and close it in one go.
					if _, err := tx.Exec(ctx, `INSERT INTO findings (tenant_id, kind, fingerprint, severity, title, detail, status, first_seen_at, resolved_at, resolution)
						VALUES ($1, 'github_governance', $2, $3, $4, $5, 'resolved', $6, $6, 'restored by Keel')`, tenant, fp, it.Severity, title, detail, now); err != nil {
						return err
					}
					continue
				}
				open[fp] = true
				if _, err := tx.Exec(ctx, `INSERT INTO findings (tenant_id, kind, fingerprint, severity, title, detail, first_seen_at)
					VALUES ($1, 'github_governance', $2, $3, $4, $5, $6)
					ON CONFLICT (tenant_id, fingerprint) WHERE status = 'open' DO UPDATE SET last_seen_at = now(), detail = excluded.detail`, tenant, fp, it.Severity, title, detail, now); err != nil {
					return err
				}
			}
			rows, err := tx.Query(ctx, `SELECT fingerprint FROM findings WHERE kind = 'github_governance' AND status = 'open' AND fingerprint LIKE $1`, prefix+"%")
			if err != nil {
				return err
			}
			fps, err := pgx.CollectRows(rows, pgx.RowTo[string])
			if err != nil {
				return err
			}
			for _, fp := range fps {
				if !open[fp] {
					if _, err := tx.Exec(ctx, `UPDATE findings SET status = 'resolved', resolved_at = $2, resolution = 'matches policy' WHERE tenant_id = current_tenant_id() AND fingerprint = $1 AND status = 'open'`, fp, now); err != nil {
						return err
					}
				}
			}
			if tenant != *home {
				return nil
			}
			fixed := 0
			for _, it := range rep.Items {
				if it.Fixed {
					fixed++
				}
			}
			_, err = activity.Record(ctx, tx, activity.Activity{TenantID: tenant, Source: "keel/github-governance", Type: "keel.github_governance.reconciled",
				Subject: "github/" + rep.Owner, Operation: "ReconcileGitHub", Kind: activity.Update, Actor: keelActor, Outcome: activity.Success,
				Resources:    []activity.Resource{{Type: "github_owner", UID: rep.Owner}},
				StatusDetail: fmt.Sprintf("%s plan %s (%s): %d repos, %d drift, %d restored", rep.Version, rep.Plan, rep.Mode, rep.Repos, len(rep.Items), fixed)})
			return err
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}
