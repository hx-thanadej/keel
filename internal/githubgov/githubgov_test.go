package githubgov_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/ghapi"
	"github.com/hx-thanadej/keel/internal/githubgov"
	"github.com/hx-thanadej/keel/internal/store"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

type fakeRepo struct {
	Name     string
	Private  bool
	Props    map[string]string
	SS, PP   bool
	Rulesets map[int64]githubgov.Ruleset
}

type fakeGitHub struct {
	actions  map[string]any
	mu       sync.Mutex
	plan     string
	schema   []githubgov.Property
	subKeys  []string
	rulesets map[int64]githubgov.Ruleset
	repos    []*fakeRepo
	nextID   int64
}

func (f *fakeGitHub) repo(name string) *fakeRepo {
	for _, r := range f.repos {
		if r.Name == name {
			return r
		}
	}
	return nil
}

func write(w http.ResponseWriter, v any) { _ = json.NewEncoder(w).Encode(v) }

func (f *fakeGitHub) server(t *testing.T) *httptest.Server {
	mux := http.NewServeMux()
	lock := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			f.mu.Lock()
			defer f.mu.Unlock()
			h(w, r)
		}
	}
	mux.HandleFunc("GET /orgs/acme", lock(func(w http.ResponseWriter, _ *http.Request) {
		write(w, map[string]any{"plan": map[string]any{"name": f.plan}})
	}))
	mux.HandleFunc("GET /orgs/acme/properties/schema", lock(func(w http.ResponseWriter, _ *http.Request) { write(w, f.schema) }))
	mux.HandleFunc("PATCH /orgs/acme/properties/schema", lock(func(w http.ResponseWriter, r *http.Request) {
		var in struct{ Properties []githubgov.Property }
		_ = json.NewDecoder(r.Body).Decode(&in)
		f.schema = in.Properties
		write(w, f.schema)
	}))
	mux.HandleFunc("GET /orgs/acme/actions/oidc/customization/sub", lock(func(w http.ResponseWriter, _ *http.Request) {
		write(w, map[string]any{"include_claim_keys": f.subKeys})
	}))
	mux.HandleFunc("PUT /orgs/acme/actions/oidc/customization/sub", lock(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Keys []string `json:"include_claim_keys"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		f.subKeys = in.Keys
		w.WriteHeader(http.StatusCreated)
	}))
	rulesetRoutes := func(prefix string, get func(*http.Request) map[int64]githubgov.Ruleset) {
		mux.HandleFunc("GET "+prefix, lock(func(w http.ResponseWriter, r *http.Request) {
			var out []map[string]any
			for id := range get(r) {
				out = append(out, map[string]any{"id": id})
			}
			write(w, out)
		}))
		mux.HandleFunc("GET "+prefix+"/{id}", lock(func(w http.ResponseWriter, r *http.Request) {
			id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
			write(w, get(r)[id])
		}))
		mux.HandleFunc("POST "+prefix, lock(func(w http.ResponseWriter, r *http.Request) {
			var rs githubgov.Ruleset
			_ = json.NewDecoder(r.Body).Decode(&rs)
			f.nextID++
			rs.ID = f.nextID
			get(r)[rs.ID] = rs
			write(w, rs)
		}))
		mux.HandleFunc("PUT "+prefix+"/{id}", lock(func(w http.ResponseWriter, r *http.Request) {
			id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
			var rs githubgov.Ruleset
			_ = json.NewDecoder(r.Body).Decode(&rs)
			rs.ID = id
			get(r)[id] = rs
			write(w, rs)
		}))
	}
	rulesetRoutes("/orgs/acme/rulesets", func(*http.Request) map[int64]githubgov.Ruleset { return f.rulesets })
	rulesetRoutes("/repos/acme/{repo}/rulesets", func(r *http.Request) map[int64]githubgov.Ruleset { return f.repo(r.PathValue("repo")).Rulesets })
	mux.HandleFunc("GET /orgs/acme/repos", lock(func(w http.ResponseWriter, _ *http.Request) {
		var out []map[string]any
		for _, r := range f.repos {
			st := func(b bool) map[string]string {
				if b {
					return map[string]string{"status": "enabled"}
				}
				return map[string]string{"status": "disabled"}
			}
			out = append(out, map[string]any{"name": r.Name, "private": r.Private, "archived": false,
				"security_and_analysis": map[string]any{"secret_scanning": st(r.SS), "secret_scanning_push_protection": st(r.PP)}})
		}
		write(w, out)
	}))
	mux.HandleFunc("GET /orgs/acme/properties/values", lock(func(w http.ResponseWriter, _ *http.Request) {
		var out []map[string]any
		for _, r := range f.repos {
			var ps []map[string]any
			for k, v := range r.Props {
				ps = append(ps, map[string]any{"property_name": k, "value": v})
			}
			out = append(out, map[string]any{"repository_name": r.Name, "properties": ps})
		}
		write(w, out)
	}))
	for _, path := range []string{"", "/selected-actions", "/workflow", "/fork-pr-contributor-approval"} {
		key := path
		mux.HandleFunc("GET /orgs/acme/actions/permissions"+path, lock(func(w http.ResponseWriter, _ *http.Request) {
			if f.actions == nil {
				f.actions = map[string]any{}
			}
			v, _ := f.actions[key].(map[string]any)
			if v == nil {
				v = map[string]any{}
			}
			write(w, v)
		}))
		mux.HandleFunc("PUT /orgs/acme/actions/permissions"+path, lock(func(w http.ResponseWriter, r *http.Request) {
			var in map[string]any
			_ = json.NewDecoder(r.Body).Decode(&in)
			if f.actions == nil {
				f.actions = map[string]any{}
			}
			f.actions[key] = in
			w.WriteHeader(http.StatusNoContent)
		}))
	}
	mux.HandleFunc("PATCH /repos/acme/{repo}", lock(func(w http.ResponseWriter, r *http.Request) {
		rp := f.repo(r.PathValue("repo"))
		if rp.Private && f.plan == "free" {
			http.Error(w, `{"message":"Secret scanning is not available"}`, http.StatusUnprocessableEntity)
			return
		}
		rp.SS, rp.PP = true, true
		write(w, map[string]any{})
	}))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

type world struct {
	s         *store.Store
	home, tat string
}

func setup(t *testing.T) world {
	ctx := context.Background()
	s := storetest.New(t)
	w := world{s: s}
	w.home, _ = s.CreateTenant(ctx, "harmonyx", "HarmonyX", true)
	w.tat, _ = s.CreateTenant(ctx, "tat", "TAT", false)
	return w
}

func findings(t *testing.T, w world, tenant string) map[string]string {
	out := map[string]string{}
	if err := w.s.InTenant(context.Background(), tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(context.Background(), `SELECT fingerprint, severity FROM findings WHERE kind = 'github_governance' AND status = 'open'`)
		if err != nil {
			return err
		}
		for rows.Next() {
			var fp, sev string
			if err := rows.Scan(&fp, &sev); err != nil {
				return err
			}
			out[fp] = sev
		}
		return rows.Err()
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

var policy = githubgov.Default([]string{"ci / test"})

func TestTeamPlanOrgIsReconciled(t *testing.T) {
	w := setup(t)
	f := &fakeGitHub{plan: "team", rulesets: map[int64]githubgov.Ruleset{}, subKeys: []string{"repo", "context"},
		repos: []*fakeRepo{
			{Name: "crm-api", Private: true, Props: map[string]string{"keel-tenant": "tat", "keel-project": "tat-crm", "keel-tier": "prod"}, Rulesets: map[int64]githubgov.Ruleset{}},
			{Name: "scratch", Private: true, Props: map[string]string{}, SS: true, PP: true, Rulesets: map[int64]githubgov.Ruleset{}},
		}}
	srv := f.server(t)
	api := githubgov.GitHub{Client: ghapi.Client{BaseURL: srv.URL}, Login: "acme", Org: true}
	ctx := context.Background()

	rep, err := githubgov.Reconciler{Store: w.s, API: api, Policy: policy}.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Mode != "org-rulesets" || rep.Repos != 2 {
		t.Fatalf("report %+v", rep)
	}
	home, tat := findings(t, w, w.home), findings(t, w, w.tat)
	for _, fp := range []string{"github:acme::actions", "github:acme::property:keel-tenant", "github:acme::oidc_subject_template", "github:acme::ruleset:keel-default-branch", "github:acme::ruleset:keel-prod-tier", "github:acme:scratch:properties"} {
		if home[fp] == "" {
			t.Errorf("home lacks %s: %v", fp, home)
		}
	}
	if tat["github:acme:crm-api:secret_scanning"] != "high" || len(tat) != 1 {
		t.Errorf("tat findings %v", tat)
	}

	// Remediation restores everything Keel can, and the next run is clean except what a person must fix.
	rep, err = githubgov.Reconciler{Store: w.s, API: api, Policy: policy, Remediate: true}.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if perms, _ := f.actions[""].(map[string]any); perms["sha_pinning_required"] != true || perms["allowed_actions"] != "selected" ||
		f.actions["/workflow"].(map[string]any)["default_workflow_permissions"] != "read" || f.actions["/fork-pr-contributor-approval"].(map[string]any)["approval_policy"] != "all_external_contributors" {
		t.Fatalf("actions not restored: %v", f.actions)
	}
	if len(f.rulesets) != 2 || len(f.schema) != 3 || f.subKeys[1] != "repository_id" || !f.repo("crm-api").PP {
		t.Fatalf("not restored: rulesets %d schema %d sub %v", len(f.rulesets), len(f.schema), f.subKeys)
	}
	if got := findings(t, w, w.tat); len(got) != 0 {
		t.Fatalf("tat still open %v", got)
	}
	if got := findings(t, w, w.home); len(got) != 1 || got["github:acme:scratch:properties"] == "" {
		t.Fatalf("home open %v (only the unlabelled repo should remain)", got)
	}

	// Someone weakens the prod ruleset to zero reviews.
	for id, rs := range f.rulesets {
		if rs.Name == "keel-prod-tier" {
			for i := range rs.Rules {
				if rs.Rules[i].Type == "pull_request" {
					rs.Rules[i].Parameters["required_approving_review_count"] = 0
				}
			}
			f.rulesets[id] = rs
		}
	}
	if _, err := (githubgov.Reconciler{Store: w.s, API: api, Policy: policy}).Run(ctx); err != nil {
		t.Fatal(err)
	}
	if findings(t, w, w.home)["github:acme::ruleset:keel-prod-tier"] != "high" {
		t.Fatalf("weakened ruleset not reported: %v", findings(t, w, w.home))
	}
}

func TestFreePlanFallsBackAndReportsWhatItCannotEnforce(t *testing.T) {
	w := setup(t)
	f := &fakeGitHub{plan: "free", rulesets: map[int64]githubgov.Ruleset{}, subKeys: policy.SubClaimKeys,
		schema: policy.Properties,
		repos: []*fakeRepo{
			{Name: "site", Private: false, Props: map[string]string{"keel-tenant": "tat", "keel-project": "web", "keel-tier": "prod"}, Rulesets: map[int64]githubgov.Ruleset{}},
			{Name: "secret", Private: true, Props: map[string]string{"keel-tenant": "tat", "keel-project": "web", "keel-tier": "prod"}, Rulesets: map[int64]githubgov.Ruleset{}},
		}}
	srv := f.server(t)
	api := githubgov.GitHub{Client: ghapi.Client{BaseURL: srv.URL}, Login: "acme", Org: true}
	rep, err := githubgov.Reconciler{Store: w.s, API: api, Policy: policy, Remediate: true}.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Mode != "repo-rulesets" || len(f.rulesets) != 0 || len(f.repo("site").Rulesets) != 1 {
		t.Fatalf("mode %s org %d site %d", rep.Mode, len(f.rulesets), len(f.repo("site").Rulesets))
	}
	got := findings(t, w, w.tat)
	if got["github:acme:secret:rulesets"] != "high" || got["github:acme:secret:secret_scanning"] != "high" || got["github:acme:site:secret_scanning"] != "" {
		t.Fatalf("tat findings %v", got)
	}
}
