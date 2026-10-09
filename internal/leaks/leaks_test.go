package leaks_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
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
	if err := svc.Process(ctx, "acme/scratch", 8); err != nil {
		t.Fatal(err)
	}
	if title, _ := finding(home); !strings.Contains(title, "Leaked tencent access key AKIDbbbb") {
		t.Fatalf("home finding %q", title)
	}
	storetest.ClockedFindings(t, s, "leaked_key")
}
