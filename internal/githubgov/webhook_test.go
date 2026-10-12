package githubgov_test

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/githubgov"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

func receiver(w world) githubgov.Receiver {
	return githubgov.Receiver{Store: w.s, Owner: "acme", Policy: policy, Now: storetest.Clock()}
}

// repo is a webhook repository object owned by Tenant slug tenant ("" = no keel-tenant property).
func repo(name, tenant string) map[string]any {
	props := map[string]any{}
	if tenant != "" {
		props["keel-tenant"] = tenant
	}
	return map[string]any{"name": name, "full_name": "acme/" + name, "custom_properties": props}
}

func payload(t *testing.T, org string, fields map[string]any) []byte {
	t.Helper()
	p := map[string]any{"organization": map[string]any{"login": org}, "sender": map[string]any{"login": "mallory", "type": "User"}}
	maps.Copy(p, fields)
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func activityTypes(t *testing.T, w world, tenant string) []string {
	t.Helper()
	var out []string
	if err := w.s.InTenant(context.Background(), tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(context.Background(), `SELECT type FROM activities WHERE source = 'github/org-webhook' ORDER BY seq`)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, pgx.RowTo[string])
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func keys(m map[string]string) []string { return slices.Sorted(maps.Keys(m)) }

// ruleset is a Keel policy ruleset as GitHub reports it in a webhook, after edit changes it.
func ruleset(t *testing.T, name string, org bool, edit func(*githubgov.Ruleset)) map[string]any {
	t.Helper()
	var spec githubgov.RulesetSpec
	for _, s := range policy.Rulesets {
		if s.Name == name {
			spec = s
		}
	}
	if spec.Name == "" {
		spec = githubgov.RulesetSpec{Name: name, Reviews: 1}
	}
	rs := spec.Build(org)
	b, _ := json.Marshal(rs)
	var round githubgov.Ruleset // as GitHub sends it: numbers are JSON numbers
	_ = json.Unmarshal(b, &round)
	if edit != nil {
		edit(&round)
	}
	b, _ = json.Marshal(round)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	out["id"] = 42
	out["source_type"] = map[bool]string{true: "Organization", false: "Repository"}[org]
	return out
}

func setParam(rule, key string, v any) func(*githubgov.Ruleset) {
	return func(rs *githubgov.Ruleset) {
		for i := range rs.Rules {
			if rs.Rules[i].Type == rule {
				rs.Rules[i].Parameters[key] = v
			}
		}
	}
}

func security(secretScanning, pushProtection string) map[string]any {
	return map[string]any{"secret_scanning": map[string]any{"status": secretScanning}, "secret_scanning_push_protection": map[string]any{"status": pushProtection}}
}

func TestEveryGovernanceEventIsRecordedAsAnActivity(t *testing.T) {
	w := setup(t)
	r := receiver(w)
	ctx := context.Background()
	crm := repo("crm-api", "tat")
	events := []struct {
		event  string
		fields map[string]any
		tenant string
		want   string
	}{
		{"repository_ruleset", map[string]any{"action": "created", "repository": crm, "repository_ruleset": ruleset(t, "team-rules", false, nil)}, w.tat, "github.repository_ruleset.created"},
		{"branch_protection_rule", map[string]any{"action": "edited", "repository": crm, "rule": map[string]any{"name": "main"}}, w.tat, "github.branch_protection_rule.edited"},
		{"branch_protection_configuration", map[string]any{"action": "disabled", "repository": crm}, w.tat, "github.branch_protection_configuration.disabled"},
		{"security_and_analysis", map[string]any{"repository": crm}, w.tat, "github.security_and_analysis"},
		{"repository", map[string]any{"action": "privatized", "repository": crm}, w.tat, "github.repository.privatized"},
		{"public", map[string]any{"repository": crm}, w.tat, "github.public"},
		{"member", map[string]any{"action": "added", "repository": crm, "member": map[string]any{"login": "eve"}}, w.tat, "github.member.added"},
		{"membership", map[string]any{"action": "added", "scope": "team", "member": map[string]any{"login": "eve"}, "team": map[string]any{"slug": "crm"}}, w.home, "github.membership.added"},
		{"team", map[string]any{"action": "created", "team": map[string]any{"slug": "crm"}}, w.home, "github.team.created"},
		{"organization", map[string]any{"action": "member_added", "membership": map[string]any{"user": map[string]any{"login": "eve"}}}, w.home, "github.organization.member_added"},
	}
	want := map[string][]string{}
	for i, e := range events {
		if !githubgov.Governs(e.event) {
			t.Fatalf("%s is not routed to governance", e.event)
		}
		if err := r.Receive(ctx, "d-"+string(rune('a'+i)), e.event, payload(t, "acme", e.fields)); err != nil {
			t.Fatalf("%s: %v", e.event, err)
		}
		want[e.tenant] = append(want[e.tenant], e.want)
	}
	for _, tenant := range []string{w.home, w.tat} {
		if got := activityTypes(t, w, tenant); !slices.Equal(got, want[tenant]) {
			t.Errorf("tenant %s activities %v, want %v", tenant, got, want[tenant])
		}
	}
	if githubgov.Governs("secret_scanning_alert") || githubgov.Governs("push") {
		t.Error("non-governance events must stay with the existing receiver")
	}
	if len(findings(t, w, w.home))+len(findings(t, w, w.tat)) != 0 {
		t.Errorf("no event above weakens a Keel protection: home %v tat %v", findings(t, w, w.home), findings(t, w, w.tat))
	}
}

func TestWeakeningAKeelProtectionRaisesAFindingAndStrengtheningDoesNot(t *testing.T) {
	w := setup(t)
	r := receiver(w)
	ctx := context.Background()
	cases := []struct {
		name, event string
		fields      map[string]any
	}{
		{"deleted", "repository_ruleset", map[string]any{"action": "deleted", "repository": repo("deleted", "tat"), "repository_ruleset": ruleset(t, "keel-default-branch", false, nil)}},
		{"fewer reviews", "repository_ruleset", map[string]any{"action": "edited", "repository_ruleset": ruleset(t, "keel-prod-tier", true, setParam("pull_request", "required_approving_review_count", 0))}},
		{"not enforced", "repository_ruleset", map[string]any{"action": "edited", "repository": repo("evaluate", "tat"), "repository_ruleset": ruleset(t, "keel-default-branch", false, func(rs *githubgov.Ruleset) { rs.Enforcement = "evaluate" })}},
		{"bypass", "repository_ruleset", map[string]any{"action": "edited", "repository": repo("bypass", "tat"), "repository_ruleset": ruleset(t, "keel-default-branch", false, func(rs *githubgov.Ruleset) {
			rs.BypassActors = []any{map[string]any{"actor_type": "OrganizationAdmin"}}
		})}},
		{"rule removed", "repository_ruleset", map[string]any{"action": "edited", "repository": repo("norule", "tat"), "repository_ruleset": ruleset(t, "keel-default-branch", false, func(rs *githubgov.Ruleset) { rs.Rules = rs.Rules[1:] })}},
		{"check removed", "repository_ruleset", map[string]any{"action": "edited", "repository": repo("nocheck", "tat"), "repository_ruleset": ruleset(t, "keel-default-branch", false, setParam("required_status_checks", "required_status_checks", []any{}))}},
		{"branch excluded", "repository_ruleset", map[string]any{"action": "edited", "repository": repo("excluded", "tat"), "repository_ruleset": ruleset(t, "keel-default-branch", false, func(rs *githubgov.Ruleset) {
			rs.Conditions["ref_name"] = map[string]any{"include": []any{"~DEFAULT_BRANCH"}, "exclude": []any{"~DEFAULT_BRANCH"}}
		})}},
		{"push protection off", "security_and_analysis", map[string]any{"repository": map[string]any{"name": "pp", "full_name": "acme/pp", "custom_properties": map[string]any{"keel-tenant": "tat"}, "security_and_analysis": security("enabled", "disabled")},
			"changes": map[string]any{"from": map[string]any{"security_and_analysis": security("enabled", "enabled")}}}},

		{"stricter reviews and an extra rule", "repository_ruleset", map[string]any{"action": "edited", "repository": repo("stricter", "tat"), "repository_ruleset": ruleset(t, "keel-default-branch", false, func(rs *githubgov.Ruleset) {
			setParam("pull_request", "required_approving_review_count", 3)(rs)
			setParam("pull_request", "require_last_push_approval", true)(rs)
			rs.Rules = append(rs.Rules, githubgov.Rule{Type: "required_signatures"})
		})}},
		{"more branches", "repository_ruleset", map[string]any{"action": "edited", "repository": repo("broader", "tat"), "repository_ruleset": ruleset(t, "keel-default-branch", false, func(rs *githubgov.Ruleset) {
			rs.Conditions["ref_name"] = map[string]any{"include": []any{"~DEFAULT_BRANCH", "refs/heads/release/*"}, "exclude": []any{}}
		})}},
		{"someone else's ruleset", "repository_ruleset", map[string]any{"action": "deleted", "repository": repo("theirs", "tat"), "repository_ruleset": ruleset(t, "team-rules", false, nil)}},
		{"secret scanning on", "security_and_analysis", map[string]any{"repository": map[string]any{"name": "ss", "full_name": "acme/ss", "custom_properties": map[string]any{"keel-tenant": "tat"}, "security_and_analysis": security("enabled", "disabled")},
			"changes": map[string]any{"from": map[string]any{"security_and_analysis": security("disabled", "disabled")}}}},
		{"classic protection off", "branch_protection_configuration", map[string]any{"action": "disabled", "repository": repo("classic", "tat")}},
		{"made public", "repository", map[string]any{"action": "publicized", "repository": repo("public", "tat")}},
	}
	for i, c := range cases {
		if err := r.Receive(ctx, "w-"+string(rune('a'+i)), c.event, payload(t, "acme", c.fields)); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
	}
	wantTat := []string{
		"github:acme:bypass:ruleset:keel-default-branch",
		"github:acme:deleted:ruleset:keel-default-branch",
		"github:acme:evaluate:ruleset:keel-default-branch",
		"github:acme:excluded:ruleset:keel-default-branch",
		"github:acme:nocheck:ruleset:keel-default-branch",
		"github:acme:norule:ruleset:keel-default-branch",
		"github:acme:pp:secret_scanning",
	}
	if got := findings(t, w, w.tat); !slices.Equal(keys(got), wantTat) || got["github:acme:pp:secret_scanning"] != "high" {
		t.Errorf("tat findings %v\nwant %v", keys(got), wantTat)
	}
	if got := findings(t, w, w.home); !slices.Equal(keys(got), []string{"github:acme::ruleset:keel-prod-tier"}) {
		t.Errorf("home findings %v, want the org ruleset only", keys(got))
	}
	if n := len(activityTypes(t, w, w.tat)) + len(activityTypes(t, w, w.home)); n != len(cases) {
		t.Errorf("%d activities for %d events", n, len(cases))
	}
	storetest.ClockedFindings(t, w.s, "github_governance")
}

func TestRedeliveryRecordsOneActivityAndOneFinding(t *testing.T) {
	w := setup(t)
	r := receiver(w)
	ctx := context.Background()
	body := payload(t, "acme", map[string]any{"action": "deleted", "repository": repo("crm-api", "tat"), "repository_ruleset": ruleset(t, "keel-default-branch", false, nil)})
	if err := r.Receive(ctx, "d-1", "repository_ruleset", body); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := r.Receive(ctx, "d-1", "repository_ruleset", body); !errors.Is(err, githubgov.ErrReplay) {
			t.Fatalf("redelivery: %v", err)
		}
	}
	if got := activityTypes(t, w, w.tat); len(got) != 1 {
		t.Errorf("activities %v", got)
	}
	var n int
	if err := storetest.Superuser(t, w.s).QueryRow(ctx, `SELECT count(*) FROM findings WHERE kind = 'github_governance'`).Scan(&n); err != nil || n != 1 {
		t.Errorf("findings %d (%v), want 1", n, err)
	}

	// A different delivery of the same change updates the open Finding instead of adding one.
	if err := r.Receive(ctx, "d-2", "repository_ruleset", body); err != nil {
		t.Fatal(err)
	}
	if err := storetest.Superuser(t, w.s).QueryRow(ctx, `SELECT count(*) FROM findings WHERE kind = 'github_governance'`).Scan(&n); err != nil || n != 1 {
		t.Errorf("findings %d (%v) after a second delivery, want 1", n, err)
	}
}

func TestEventsStayInTheirTenantAndForeignOrganisationsAreIgnored(t *testing.T) {
	w := setup(t)
	r := receiver(w)
	ctx := context.Background()
	scb, err := w.s.CreateTenant(ctx, "scb", "SCB", false)
	if err != nil {
		t.Fatal(err)
	}
	weaken := func(name, tenant string) map[string]any {
		return map[string]any{"action": "deleted", "repository": repo(name, tenant), "repository_ruleset": ruleset(t, "keel-default-branch", false, nil)}
	}
	if err := r.Receive(ctx, "t-1", "repository_ruleset", payload(t, "acme", weaken("crm-api", "tat"))); err != nil {
		t.Fatal(err)
	}
	if err := r.Receive(ctx, "t-2", "repository_ruleset", payload(t, "ACME", weaken("unlabelled", "no-such-tenant"))); err != nil {
		t.Fatal(err)
	}
	if err := r.Receive(ctx, "t-3", "repository_ruleset", payload(t, "evil", weaken("scb-api", "scb"))); !errors.Is(err, githubgov.ErrForeignOrg) {
		t.Fatalf("foreign organisation: %v", err)
	}
	if err := r.Receive(ctx, "t-4", "team", []byte(`{"action":"created","team":{"slug":"x"}}`)); !errors.Is(err, githubgov.ErrForeignOrg) {
		t.Fatalf("no organisation: %v", err)
	}

	if got := keys(findings(t, w, w.tat)); !slices.Equal(got, []string{"github:acme:crm-api:ruleset:keel-default-branch"}) {
		t.Errorf("tat findings %v", got)
	}
	if got := keys(findings(t, w, w.home)); !slices.Equal(got, []string{"github:acme:unlabelled:ruleset:keel-default-branch"}) {
		t.Errorf("home findings %v (a repository without a known Tenant belongs to the home Tenant, as in the reconciler)", got)
	}
	if got := findings(t, w, scb); len(got) != 0 {
		t.Errorf("scb findings %v", got)
	}
	if got := activityTypes(t, w, scb); len(got) != 0 {
		t.Errorf("scb activities %v", got)
	}
	if len(activityTypes(t, w, w.tat)) != 1 || len(activityTypes(t, w, w.home)) != 1 {
		t.Errorf("tat %v home %v", activityTypes(t, w, w.tat), activityTypes(t, w, w.home))
	}
	var n int
	if err := storetest.Superuser(t, w.s).QueryRow(ctx, `SELECT count(*) FROM webhook_deliveries WHERE delivery_id IN ('t-3', 't-4')`).Scan(&n); err != nil || n != 0 {
		t.Errorf("ignored deliveries recorded: %d (%v)", n, err)
	}
}
