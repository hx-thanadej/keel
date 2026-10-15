package connections_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/connections"
	"github.com/hx-thanadej/keel/internal/secrets"
	"github.com/hx-thanadej/keel/internal/store"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

const (
	secretID  = "TESTIDz8krbsJ5yKBZQpn74WFkmLPx3FAKE"
	secretKey = "Gu5t9xGARNpq86cd98joQYCN3EXAMPLEKEY"
)

var admin = activity.Actor{Type: activity.ActorHuman, UID: "user:admin@harmonyx.co"}

func sealer(t *testing.T, previous ...string) (*secrets.Sealer, string) {
	t.Helper()
	k := make([]byte, 32)
	_, _ = rand.Read(k)
	key := base64.StdEncoding.EncodeToString(k)
	vars := map[string]string{"KEEL_SECRETS_KEY": key}
	if len(previous) > 0 {
		vars["KEEL_SECRETS_KEY_PREVIOUS"] = previous[0]
	}
	s, err := secrets.FromEnv(func(n string) string { return vars[n] })
	if err != nil {
		t.Fatal(err)
	}
	return s, key
}

type world struct {
	st   *store.Store
	home string
	svc  connections.Service
}

func newWorld(t *testing.T) world {
	t.Helper()
	st := storetest.New(t)
	home, err := st.CreateTenant(t.Context(), "harmonyx", "HarmonyX", true)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := sealer(t)
	return world{st: st, home: home, svc: connections.Service{Store: st, Sealer: s,
		Identify: func(_ context.Context, k connections.Keys, region string) (string, error) {
			if k.SecretID != secretID || k.SecretKey != secretKey {
				return "", errors.New("AuthFailure.SecretIdNotFound")
			}
			return "100000000001", nil
		}}}
}

func input() connections.Input {
	return connections.Input{Provider: "tencent", Name: "HarmonyX payer", PayerUIN: "100000000001", DefaultRegion: "ap-bangkok",
		OrgRegion: "ap-bangkok", MemberRole: "OrganizationAccessControlRole", Keys: connections.Keys{SecretID: secretID, SecretKey: secretKey}}
}

func (w world) create(t *testing.T) connections.Connection {
	t.Helper()
	c, err := w.svc.Create(t.Context(), input(), admin)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCreateSealsKeysAndShowsThemMasked(t *testing.T) {
	w := newWorld(t)
	c := w.create(t)
	if c.Mode != connections.ReadOnly || c.SecretID != "****FAKE" || c.ID == "" {
		t.Fatalf("created %+v", c)
	}
	list, err := w.svc.List(t.Context())
	if err != nil || len(list) != 1 || list[0].SecretID != "****FAKE" {
		t.Fatalf("list %+v %v", list, err)
	}
	for _, s := range []string{fmt.Sprintf("%v", list), fmt.Sprintf("%+v", input()), fmt.Sprintf("%#v", input().Keys)} {
		if strings.Contains(s, secretID) || strings.Contains(s, secretKey) {
			t.Fatalf("printing shows a key: %s", s)
		}
	}
	var sealedID, sealedKey []byte
	if err := storetest.Superuser(t, w.st).QueryRow(t.Context(), `SELECT secret_id_sealed, secret_key_sealed FROM cloud_connections`).Scan(&sealedID, &sealedKey); err != nil {
		t.Fatal(err)
	}
	for _, sealed := range [][]byte{sealedID, sealedKey} {
		if bytes.Contains(sealed, []byte(secretID)) || bytes.Contains(sealed, []byte(secretKey)) {
			t.Fatal("the table holds a key in plaintext")
		}
	}
	id, key, ok, err := w.svc.TencentKey(t.Context())
	if err != nil || !ok || id != secretID || key != secretKey {
		t.Fatalf("TencentKey = %q %q %v %v", id, key, ok, err)
	}
}

func TestNoConnectionIsNotAnError(t *testing.T) {
	w := newWorld(t)
	if _, _, ok, err := w.svc.TencentKey(t.Context()); ok || err != nil {
		t.Fatalf("ok %v err %v", ok, err)
	}
	w.svc.Sealer = nil
	if _, _, ok, err := w.svc.TencentKey(t.Context()); ok || err != nil {
		t.Fatalf("no key, no rows: ok %v err %v", ok, err)
	}
}

func TestWrongKeyDoesNotOpen(t *testing.T) {
	w := newWorld(t)
	w.create(t)
	other, _ := sealer(t)
	w.svc.Sealer = other
	if _, _, _, err := w.svc.TencentKey(t.Context()); !errors.Is(err, secrets.ErrUnknownKey) {
		t.Fatalf("other key: %v", err)
	}
	w.svc.Sealer = nil
	if _, _, _, err := w.svc.TencentKey(t.Context()); !errors.Is(err, connections.ErrNoSecretsKey) {
		t.Fatalf("no key: %v", err)
	}
}

// TestSealedValuesAreBoundToTheirRow: an attacker with database access who
// moves a sealed value to another column or row gets nothing.
func TestSealedValuesAreBoundToTheirRow(t *testing.T) {
	for name, attack := range map[string]string{
		"swapped columns": `UPDATE cloud_connections SET secret_id_sealed = secret_key_sealed, secret_key_sealed = secret_id_sealed`,
		"moved to an id":  `UPDATE cloud_connections SET id = '00000000-0000-7000-8000-000000000001'`,
	} {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t)
			w.create(t)
			if _, err := storetest.Superuser(t, w.st).Exec(t.Context(), attack); err != nil {
				t.Fatal(err)
			}
			if _, _, _, err := w.svc.TencentKey(t.Context()); !errors.Is(err, secrets.ErrCorrupt) {
				t.Fatalf("err %v, want ErrCorrupt", err)
			}
		})
	}
	t.Run("moved to another Tenant", func(t *testing.T) {
		w := newWorld(t)
		c := w.create(t)
		other, err := w.st.CreateTenant(t.Context(), "tat", "TAT", false)
		if err != nil {
			t.Fatal(err)
		}
		su := storetest.Superuser(t, w.st)
		if _, err := su.Exec(t.Context(), `UPDATE cloud_connections SET tenant_id = $1`, other); err != nil {
			t.Fatal(err)
		}
		for _, q := range []string{`UPDATE tenants SET is_home = false WHERE id <> $1`, `UPDATE tenants SET is_home = true WHERE id = $1`} {
			if _, err := su.Exec(t.Context(), q, other); err != nil {
				t.Fatal(err)
			}
		}
		if _, _, _, err := w.svc.TencentKey(t.Context()); !errors.Is(err, secrets.ErrCorrupt) {
			t.Fatalf("connection %s in another Tenant: %v, want ErrCorrupt", c.ID, err)
		}
	})
}

func TestConnectionsAreInvisibleToOtherTenants(t *testing.T) {
	w := newWorld(t)
	w.create(t)
	other, err := w.st.CreateTenant(t.Context(), "tat", "TAT", false)
	if err != nil {
		t.Fatal(err)
	}
	var n int
	if err := w.st.InTenant(t.Context(), other, func(tx pgx.Tx) error {
		return tx.QueryRow(t.Context(), `SELECT count(*) FROM cloud_connections`).Scan(&n)
	}); err != nil || n != 0 {
		t.Fatalf("another Tenant sees %d connections (%v)", n, err)
	}
	err = w.st.InTenant(t.Context(), other, func(tx pgx.Tx) error {
		_, err := tx.Exec(t.Context(), `INSERT INTO cloud_connections (id, tenant_id, provider, name, payer_uin, default_region, secret_id_sealed, secret_key_sealed, secret_id_last4, created_at, created_by, updated_at)
			VALUES (uuidv7(), $1, 'tencent', 'x', '100000000001', 'ap-bangkok', '\x00', '\x00', 'abcd', now(), 'x', now())`, w.home)
		return err
	})
	if err == nil {
		t.Fatal("another Tenant wrote a connection into the home Tenant")
	}
}

func TestCreateValidates(t *testing.T) {
	w := newWorld(t)
	for name, mutate := range map[string]func(*connections.Input){
		"write mode":        func(i *connections.Input) { i.Mode = "read_write" },
		"other provider":    func(i *connections.Input) { i.Provider = "aws" },
		"no name":           func(i *connections.Input) { i.Name = " " },
		"payer not a uin":   func(i *connections.Input) { i.PayerUIN = "abc" },
		"no region":         func(i *connections.Input) { i.DefaultRegion = "" },
		"bad member role":   func(i *connections.Input) { i.MemberRole = "a role" },
		"short secret id":   func(i *connections.Input) { i.SecretID = "AKID" },
		"no secret key":     func(i *connections.Input) { i.SecretKey = "" },
		"space in the key":  func(i *connections.Input) { i.SecretKey = "Gu5t9xGARNpq86cd 98joQYCN3EXAMPLE" },
		"bad org region":    func(i *connections.Input) { i.OrgRegion = "Bangkok!" },
		"secret id too big": func(i *connections.Input) { i.SecretID = strings.Repeat("A", 200) },
	} {
		in := input()
		mutate(&in)
		if _, err := w.svc.Create(t.Context(), in, admin); !errors.Is(err, connections.ErrInvalid) {
			t.Errorf("%s: %v, want ErrInvalid", name, err)
		}
	}
	w.create(t)
	if _, err := w.svc.Create(t.Context(), input(), admin); !errors.Is(err, connections.ErrConflict) {
		t.Fatalf("second tencent connection: %v, want ErrConflict", err)
	}
	w.svc.Sealer = nil
	if _, err := w.svc.Create(t.Context(), input(), admin); !errors.Is(err, connections.ErrNoSecretsKey) {
		t.Fatalf("no KEEL_SECRETS_KEY: %v", err)
	}
}

func TestRotateTestDeleteAndActivitiesCarryNoSecret(t *testing.T) {
	w := newWorld(t)
	c := w.create(t)
	tested, err := w.svc.Test(t.Context(), c.ID, admin)
	if err != nil || tested.LastTest == nil || !tested.LastTest.OK || tested.LastTest.CallerUIN != "100000000001" {
		t.Fatalf("test %+v %v", tested.LastTest, err)
	}
	name := "Renamed"
	renamed, err := w.svc.Update(t.Context(), c.ID, connections.Change{Name: &name}, admin)
	if err != nil || renamed.Name != "Renamed" || renamed.RotatedAt != nil || renamed.LastTest == nil {
		t.Fatalf("rename %+v %v", renamed, err)
	}
	newID, newKey := "TESTIDrotatedrotatedrotated9ZZZ", "rotated-secret-key-0123456789"
	rotated, err := w.svc.Update(t.Context(), c.ID, connections.Change{Keys: &connections.Keys{SecretID: newID, SecretKey: newKey}}, admin)
	if err != nil || rotated.SecretID != "****9ZZZ" || rotated.RotatedAt == nil || rotated.LastTest != nil {
		t.Fatalf("rotate %+v %v", rotated, err)
	}
	if id, key, _, _ := w.svc.TencentKey(t.Context()); id != newID || key != newKey {
		t.Fatalf("after rotation TencentKey = %q %q", id, key)
	}
	failed, err := w.svc.Test(t.Context(), c.ID, admin)
	if err != nil || failed.LastTest == nil || failed.LastTest.OK || failed.LastTest.Detail == "" {
		t.Fatalf("failing test %+v %v", failed.LastTest, err)
	}
	if _, err := w.svc.Update(t.Context(), c.ID, connections.Change{Keys: &connections.Keys{SecretID: newID}}, admin); !errors.Is(err, connections.ErrInvalid) {
		t.Fatalf("rotating half a key: %v", err)
	}
	if err := w.svc.Delete(t.Context(), c.ID, admin); err != nil {
		t.Fatal(err)
	}
	if err := w.svc.Delete(t.Context(), c.ID, admin); !errors.Is(err, connections.ErrNotFound) {
		t.Fatalf("second delete: %v", err)
	}
	if _, _, ok, err := w.svc.TencentKey(t.Context()); ok || err != nil {
		t.Fatalf("after delete: %v %v", ok, err)
	}

	var types []string
	var events string
	if err := w.st.InTenant(t.Context(), w.home, func(tx pgx.Tx) error {
		rows, err := tx.Query(t.Context(), `SELECT type, event::text FROM activities WHERE subject = $1 ORDER BY seq`, "cloud_connection/"+c.ID)
		if err != nil {
			return err
		}
		for rows.Next() {
			var typ, ev string
			if err := rows.Scan(&typ, &ev); err != nil {
				return err
			}
			types, events = append(types, typ), events+ev
		}
		return rows.Err()
	}); err != nil {
		t.Fatal(err)
	}
	want := []string{"keel.cloud_connection.created", "keel.cloud_connection.tested", "keel.cloud_connection.updated",
		"keel.cloud_connection.keys_rotated", "keel.cloud_connection.tested", "keel.cloud_connection.deleted"}
	if strings.Join(types, " ") != strings.Join(want, " ") {
		t.Fatalf("activities %v, want %v", types, want)
	}
	for _, s := range []string{secretID, secretKey, newID, newKey} {
		if strings.Contains(events, s) {
			t.Fatalf("an Activity carries key material %q", s)
		}
	}
}

// TestTestFailsWhenTheKeyIsAnotherAccount: a key that works but belongs to
// an account other than the payer is a failed test.
func TestTestFailsWhenTheKeyIsAnotherAccount(t *testing.T) {
	w := newWorld(t)
	c := w.create(t)
	w.svc.Identify = func(context.Context, connections.Keys, string) (string, error) { return "100000000999", nil }
	got, err := w.svc.Test(t.Context(), c.ID, admin)
	if err != nil || got.LastTest.OK || got.LastTest.CallerUIN != "100000000999" || !strings.Contains(got.LastTest.Detail, "100000000001") {
		t.Fatalf("%+v %v", got.LastTest, err)
	}
}

// TestTestScrubsKeysFromErrors: an STS error that echoes the key never
// reaches the stored result.
func TestTestScrubsKeysFromErrors(t *testing.T) {
	w := newWorld(t)
	c := w.create(t)
	w.svc.Identify = func(_ context.Context, k connections.Keys, _ string) (string, error) {
		return "", fmt.Errorf("SecretId %s with key %s rejected", k.SecretID, k.SecretKey)
	}
	got, err := w.svc.Test(t.Context(), c.ID, admin)
	if err != nil || strings.Contains(got.LastTest.Detail, secretID) || strings.Contains(got.LastTest.Detail, secretKey) {
		t.Fatalf("%+v %v", got.LastTest, err)
	}
}

func TestPrepare(t *testing.T) {
	w := newWorld(t)
	if err := (connections.Service{Store: w.st}).Prepare(t.Context()); err != nil {
		t.Fatalf("no connections and no key: %v", err)
	}
	w.create(t)
	if err := (connections.Service{Store: w.st}).Prepare(t.Context()); !errors.Is(err, connections.ErrNoSecretsKey) {
		t.Fatalf("connections without KEEL_SECRETS_KEY: %v", err)
	}
	other, _ := sealer(t)
	lost := connections.Service{Store: w.st, Sealer: other}
	if err := lost.Prepare(t.Context()); err != nil {
		t.Fatalf("a connection sealed with a lost key must not block start: %v", err)
	}
	if _, _, _, err := lost.TencentKey(t.Context()); !errors.Is(err, secrets.ErrUnknownKey) {
		t.Fatalf("lost key: %v, want ErrUnknownKey so Keel fails closed", err)
	}
	cs, err := lost.List(t.Context())
	if err != nil || len(cs) != 1 {
		t.Fatal(cs, err)
	}
	if err := lost.Delete(t.Context(), cs[0].ID, admin); err != nil {
		t.Fatalf("an admin cannot replace a connection after losing the key: %v", err)
	}
}

// TestRotatingKeelSecretsKey: with the old key as KEEL_SECRETS_KEY_PREVIOUS,
// Prepare reseals every connection under the new key, so the old key can
// then be dropped.
func TestRotatingKeelSecretsKey(t *testing.T) {
	w := newWorld(t)
	old, oldKey := sealer(t)
	w.svc.Sealer = old
	w.create(t)
	rotated, newKey := sealer(t, oldKey)
	if err := (connections.Service{Store: w.st, Sealer: rotated}).Prepare(t.Context()); err != nil {
		t.Fatal(err)
	}
	only, err := secrets.FromEnv(func(n string) string { return map[string]string{"KEEL_SECRETS_KEY": newKey}[n] })
	if err != nil {
		t.Fatal(err)
	}
	id, key, ok, err := (connections.Service{Store: w.st, Sealer: only}).TencentKey(t.Context())
	if err != nil || !ok || id != secretID || key != secretKey {
		t.Fatalf("after rotation with the new key alone: %q %q %v %v", id, key, ok, err)
	}
	if n := countActivities(t, w, "keel.cloud_connection.resealed"); n != 1 {
		t.Fatalf("resealed activities %d", n)
	}
}

func countActivities(t *testing.T, w world, typ string) int {
	t.Helper()
	var n int
	if err := w.st.InTenant(t.Context(), w.home, func(tx pgx.Tx) error {
		return tx.QueryRow(t.Context(), `SELECT count(*) FROM activities WHERE type = $1`, typ).Scan(&n)
	}); err != nil {
		t.Fatal(err)
	}
	return n
}
