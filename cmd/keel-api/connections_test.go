package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/cloud/tencent"
	"github.com/hx-thanadej/keel/internal/connections"
	"github.com/hx-thanadej/keel/internal/secrets"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

// TestStoredConnectionAtStart: Keel refuses to start with stored
// connections and no KEEL_SECRETS_KEY; with it, the stored key becomes the
// read-only base identity and fills only the unset Tencent settings that
// reads use, never the vending role that wires up write jobs.
func TestStoredConnectionAtStart(t *testing.T) {
	st := storetest.New(t)
	if _, err := st.CreateTenant(t.Context(), "harmonyx", "HarmonyX", true); err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	key := base64.StdEncoding.EncodeToString(raw)
	for _, env := range []string{"KEEL_SECRETS_KEY", "KEEL_SECRETS_KEY_PREVIOUS", "KEEL_TENCENT_ORG_REGION", "KEEL_TENCENT_REGION",
		"KEEL_TENCENT_PAYER_UIN", "KEEL_TENCENT_VENDING_ROLE", "KEEL_TENCENT_MEMBER_ROLE", "KEEL_ENV"} {
		t.Setenv(env, "")
	}
	t.Setenv("KEEL_TENCENT_REGION", "ap-singapore")
	sealer, _ := secrets.FromEnv(func(string) string { return key })
	if _, err := (connections.Service{Store: st, Sealer: sealer}).Create(t.Context(), connections.Input{Provider: "tencent", Name: "payer", PayerUIN: "100000000001",
		DefaultRegion: "ap-bangkok", OrgRegion: "ap-bangkok", MemberRole: "KeelReader",
		Keys: connections.Keys{SecretID: "TESTIDz8krbsJ5yKBZQpn74WFkmLPx3FAKE", SecretKey: "Gu5t9xGARNpq86cd98joQYCN3EXAMPLEKEY"}},
		activity.Actor{Type: activity.ActorHuman, UID: "user:admin"}); err != nil {
		t.Fatal(err)
	}

	if _, _, err := cloudConnections(t.Context(), st); !errors.Is(err, connections.ErrNoSecretsKey) {
		t.Fatalf("start without KEEL_SECRETS_KEY: %v", err)
	}
	t.Setenv("KEEL_SECRETS_KEY", key)
	_, storedKey, err := cloudConnections(t.Context(), st)
	if err != nil || !storedKey {
		t.Fatalf("stored key %v, err %v", storedKey, err)
	}
	for env, want := range map[string]string{"KEEL_TENCENT_ORG_REGION": "ap-bangkok", "KEEL_TENCENT_REGION": "ap-singapore",
		"KEEL_TENCENT_PAYER_UIN": "100000000001", "KEEL_TENCENT_VENDING_ROLE": "", "KEEL_TENCENT_MEMBER_ROLE": "KeelReader"} {
		if got := os.Getenv(env); got != want {
			t.Errorf("%s = %q, want %q", env, got, want)
		}
	}
	c, err := tencentCredentials(st).GetCredential()
	if err != nil || c.GetSecretId() != "TESTIDz8krbsJ5yKBZQpn74WFkmLPx3FAKE" || !tencent.IsReadOnly(c) {
		t.Fatalf("base identity %v %v, want the stored key, read-only", c, err)
	}
}

// TestStoredKeyStartsNoTencentWriteJobs: with every Tencent write job
// turned on by its settings, a writable identity starts each one, and a
// stored-key identity starts none and says why once.
func TestStoredKeyStartsNoTencentWriteJobs(t *testing.T) {
	env := map[string]string{"KEEL_TENCENT_ORG_REGION": "ap-bangkok", "KEEL_CIC_ZONE_ID": "z-1", "KEEL_TCR_REGISTRY_ID": "tcr-1",
		"KEEL_TENCENT_BUDGETS": "1", "KEEL_WASTE_CLEANUP": "1", "KEEL_ARCHIVE_BUCKET": "archive-1250000000",
		"KEEL_ARCHIVE_PROVIDER": "tencent", "KEEL_ARCHIVE_ENDPOINT": "cos.ap-bangkok.myqcloud.com", "KEEL_ARCHIVE_REGION": "ap-bangkok"}
	getenv := func(k string) string { return env[k] }
	all := tencentWrites{Vending: true, LeakDisable: true, CICGrants: true, TCRTokens: true, BudgetMirror: true, WasteCleanup: true, COSArchive: true}
	if got := tencentWriteJobs(getenv, false); got != all {
		t.Fatalf("writable identity: %+v, want every job on", got)
	}
	var logs bytes.Buffer
	defer func(l *slog.Logger) { slog.SetDefault(l) }(slog.Default())
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	if got := tencentWriteJobs(getenv, true); got != (tencentWrites{}) {
		t.Fatalf("stored key: %+v, want no write job", got)
	}
	if n := strings.Count(logs.String(), "stored-key connection"); n != 1 || !strings.Contains(logs.String(), "account vending") {
		t.Fatalf("want one line naming the jobs not started, got %q", logs.String())
	}
	logs.Reset()
	if got := tencentWriteJobs(func(string) string { return "" }, true); got != (tencentWrites{}) || logs.Len() != 0 {
		t.Fatalf("nothing configured: %+v, logs %q", got, logs.String())
	}
}
