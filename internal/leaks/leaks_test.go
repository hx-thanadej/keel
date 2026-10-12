package leaks_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/flow/flowtest"
	"github.com/hx-thanadej/keel/internal/leaks"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

type alerts map[int]string // number → secret

func (a alerts) Secret(_ context.Context, _ string, n int) (string, string, error) {
	return "tencent_cloud_secret_id", a[n], nil
}

type keys struct {
	mu       sync.Mutex
	owner    map[string]leaks.Key
	disabled []string
}

func (k *keys) Provider() string { return "tencent" }
func (k *keys) Find(_ context.Context, id string, accounts []string) (leaks.Key, bool, error) {
	key, ok := k.owner[id]
	for _, a := range accounts {
		if ok && a == key.Account {
			return key, true, nil
		}
	}
	return leaks.Key{}, false, nil
}
func (k *keys) Disable(_ context.Context, key leaks.Key) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.disabled = append(k.disabled, key.KeyID)
	return nil
}

func sign(secret, body string) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(body))
	return "sha256=" + hex.EncodeToString(m.Sum(nil))
}

func TestLeakedKeyIsDisabledAndReported(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	home, _ := s.CreateTenant(ctx, "harmonyx", "HarmonyX", true)
	tat, _ := s.CreateTenant(ctx, "tat", "TAT", false)
	if err := s.InTenant(ctx, tat, func(tx pgx.Tx) error {
		var team, project, env string
		if err := tx.QueryRow(ctx, `INSERT INTO teams (tenant_id, slug, name) VALUES ($1, 'crm', 'CRM') RETURNING id`, tat).Scan(&team); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO projects (tenant_id, team_id, slug, name) VALUES ($1, $2, 'tat-crm', 'TAT CRM') RETURNING id`, tat, team).Scan(&project); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO environments (tenant_id, project_id, name) VALUES ($1, $2, 'prod') RETURNING id`, tat, project).Scan(&env); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO cloud_accounts (tenant_id, environment_id, provider, external_id, name) VALUES ($1, $2, 'tencent', '100002', 'prod')`, tat, env)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	leaked := "AKID" + strings.Repeat("a", 32)
	unknown := "AKID" + strings.Repeat("b", 32)
	k := &keys{owner: map[string]leaks.Key{leaked: {Provider: "tencent", KeyID: leaked, Account: "100002", OwnerUin: "3001", Owner: "deploy-bot"}}}
	svc := &leaks.Service{Store: s, WebhookSecret: []byte("whsec"), Alerts: alerts{7: "SecretId=" + leaked + "\nSecretKey=xyz", 8: unknown}, Keys: map[string]leaks.Keys{"tencent": k}, Now: storetest.Clock()}
	c, _ := flowtest.Client(t, s, svc.Register)
	svc.SetClient(c)

	body := `{"action":"created","alert":{"number":7},"repository":{"full_name":"acme/crm-api"}}`
	if err := svc.Verify([]byte(body), sign("wrong", body)); !errors.Is(err, leaks.ErrSignature) {
		t.Fatalf("bad signature accepted: %v", err)
	}
	if err := svc.Verify([]byte(body), sign("whsec", body)); err != nil {
		t.Fatal(err)
	}
	if err := svc.Receive(ctx, "d-1", "secret_scanning_alert", []byte(body)); err != nil {
		t.Fatal(err)
	}
	if err := svc.Receive(ctx, "d-1", "secret_scanning_alert", []byte(body)); !errors.Is(err, leaks.ErrReplay) {
		t.Fatalf("replay: %v", err)
	}
	finding := func(tenant string) (string, string) {
		var title, sev string
		_ = s.InTenant(ctx, tenant, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT title, severity FROM findings WHERE kind = 'leaked_key' AND status = 'open'`).Scan(&title, &sev)
		})
		return title, sev
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		if title, _ := finding(tat); title != "" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("alert never processed")
		}
		time.Sleep(100 * time.Millisecond)
	}
	title, sev := finding(tat)
	k.mu.Lock()
	disabled := append([]string(nil), k.disabled...)
	k.mu.Unlock()
	if len(disabled) != 1 || disabled[0] != leaked || sev != "critical" || !strings.Contains(title, "was disabled") || strings.Contains(title, leaked) {
		t.Fatalf("disabled %v finding %q %s", disabled, title, sev)
	}
	// A key Keel does not know: platform Finding in the home Tenant, nothing disabled.
	if err := svc.Process(ctx, leaks.Repo{Name: "acme/scratch"}, 8); err != nil {
		t.Fatal(err)
	}
	if title, _ := finding(home); !strings.Contains(title, "Leaked tencent access key AKIDbbbb") {
		t.Fatalf("home finding %q", title)
	}
	storetest.ClockedFindings(t, s, "leaked_key")
}

type searched struct {
	keys
	accounts [][]string
}

func (s *searched) Find(ctx context.Context, id string, accounts []string) (leaks.Key, bool, error) {
	s.accounts = append(s.accounts, accounts)
	return s.keys.Find(ctx, id, accounts)
}

// TestLeakedKeyInAClientAccountReachesTheClient: Keel never searches a
// client-owned account (ADR-0018, #240). A key leaked from a repository a
// client Tenant's Service owns, and not found in the platform accounts, is
// raised in that client's Tenant, naming the accounts Keel did not search;
// the home Tenant gets nothing it could act on. A repository no client owns
// gets a home Finding that says what was and was not searched.
func TestLeakedKeyInAClientAccountReachesTheClient(t *testing.T) {
	ctx := context.Background()
	s := storetest.New(t)
	home, _ := s.CreateTenant(ctx, "harmonyx", "HarmonyX", true)
	tat, _ := s.CreateTenant(ctx, "tat", "TAT", false)
	if err := s.InTenant(ctx, home, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO cloud_accounts (tenant_id, provider, external_id, name) VALUES ($1, 'tencent', '200001', 'platform')`, home)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.InTenant(ctx, tat, func(tx pgx.Tx) error {
		var team, project string
		if err := tx.QueryRow(ctx, `INSERT INTO teams (tenant_id, slug, name) VALUES ($1, 'crm', 'CRM') RETURNING id`, tat).Scan(&team); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO projects (tenant_id, team_id, slug, name) VALUES ($1, $2, 'tat-crm', 'TAT CRM') RETURNING id`, tat, team).Scan(&project); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO services (tenant_id, project_id, team_id, slug, name, repository_id) VALUES ($1, $2, $3, 'crm-api', 'CRM API', 42)`, tat, project, team); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO cloud_accounts (tenant_id, provider, external_id, name, ownership, read_only_role)
			VALUES ($1, 'tencent', '100002', 'prod', 'client', '{"role_arn": "qcs::cam::uin/100002:roleName/keel-readonly"}')`, tat)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	leaked := "AKID" + strings.Repeat("a", 32)
	k := &searched{keys: keys{owner: map[string]leaks.Key{leaked: {Provider: "tencent", KeyID: leaked, Account: "100002", OwnerUin: "3001", Owner: "deploy-bot"}}}}
	svc := &leaks.Service{Store: s, Alerts: alerts{9: leaked}, Keys: map[string]leaks.Keys{"tencent": k}, Now: storetest.Clock()}
	type finding struct{ title, action, service string }
	findings := func(tenant string) []finding {
		var out []finding
		if err := s.InTenant(ctx, tenant, func(tx pgx.Tx) error {
			rows, err := tx.Query(ctx, `SELECT title, detail->>'action', coalesce(service_id::text, '') FROM findings WHERE kind = 'leaked_key' AND status = 'open' AND severity = 'critical'`)
			if err != nil {
				return err
			}
			out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (finding, error) {
				var f finding
				return f, r.Scan(&f.title, &f.action, &f.service)
			})
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return out
	}

	if err := svc.Process(ctx, leaks.Repo{ID: 42, Name: "tat/crm-api"}, 9); err != nil {
		t.Fatal(err)
	}
	for _, a := range k.accounts {
		if slices.Contains(a, "100002") {
			t.Fatalf("searched a client-owned account: %v", k.accounts)
		}
	}
	if k.disabled != nil {
		t.Fatalf("disabled %v in a client-owned account", k.disabled)
	}
	got := findings(tat)
	if len(got) != 1 || got[0].service == "" || !strings.Contains(got[0].action, "Keel does not search client-owned accounts") ||
		!strings.Contains(got[0].action, "100002") || !strings.Contains(got[0].action, "you must find this key") {
		t.Fatalf("client Tenant findings %+v: want one telling the client Keel did not search 100002 and they must find and disable the key", got)
	}
	if got := findings(home); len(got) != 0 {
		t.Fatalf("home Tenant findings %+v: want none, the platform accounts were searched and are clean", got)
	}

	// A repository no client Tenant owns: the home Tenant hears what was searched.
	if err := svc.Process(ctx, leaks.Repo{ID: 7, Name: "harmonyx/scratch"}, 9); err != nil {
		t.Fatal(err)
	}
	got = findings(home)
	if len(got) != 1 || strings.Contains(got[0].action, "could not find this key in any account it manages") ||
		!strings.Contains(got[0].action, "not in the platform-owned accounts Keel searched") || !strings.Contains(got[0].action, "100002") {
		t.Fatalf("home Tenant findings %+v: want one that says the platform accounts were searched and client-owned 100002 was not", got)
	}
}
