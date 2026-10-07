package integrity_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/integrity"
	"github.com/hx-thanadej/keel/internal/store"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

type env struct {
	s      *store.Store
	tenant string
	signer *integrity.Ed25519
	pub    ed25519.PublicKey
	sealer *integrity.Sealer
	clock  time.Time
}

func setup(t *testing.T) *env {
	t.Helper()
	s := storetest.New(t)
	tenant, err := s.CreateTenant(t.Context(), "tat", "TAT", false)
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	e := &env{s: s, tenant: tenant, pub: pub, signer: integrity.NewEd25519(priv)}
	e.clock = time.Now()
	e.sealer = &integrity.Sealer{Store: s, Signer: e.signer, Grace: time.Nanosecond, Now: func() time.Time { return e.clock }}
	return e
}

func (e *env) record(t *testing.T, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		err := e.s.InTenant(context.Background(), e.tenant, func(tx pgx.Tx) error {
			_, err := activity.Record(context.Background(), tx, activity.Activity{
				TenantID: e.tenant, Source: "test", Type: "test.event", Operation: "Test", Kind: activity.Create,
				Actor: activity.Actor{Type: activity.ActorKeel, UID: "keel:test"}, Outcome: activity.Success,
			})
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func (e *env) seal(t *testing.T) integrity.Digest {
	t.Helper()
	e.clock = e.clock.Add(time.Second)
	d, err := e.sealer.Seal(context.Background(), e.tenant)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func (e *env) verify(t *testing.T) integrity.Report {
	t.Helper()
	r, err := integrity.Verify(context.Background(), e.s, e.tenant, map[string]ed25519.PublicKey{e.signer.KeyID(): e.pub})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func mustFail(t *testing.T, r integrity.Report, want string) {
	t.Helper()
	if r.OK() {
		t.Fatalf("verification passed, want failure containing %q", want)
	}
	if !strings.Contains(strings.Join(r.Problems, "\n"), want) {
		t.Fatalf("problems %v, want one containing %q", r.Problems, want)
	}
}

func TestSealAndVerifyChain(t *testing.T) {
	e := setup(t)
	e.record(t, 5)
	d1 := e.seal(t)
	if d1.Count != 5 || len(d1.Signature) == 0 || d1.PrevSignature != nil {
		t.Fatalf("first digest %+v", d1)
	}
	e.record(t, 3)
	d2 := e.seal(t)
	if d2.Count != 3 || string(d2.PrevSignature) != string(d1.Signature) || d2.SeqFrom != d1.SeqTo {
		t.Fatalf("second digest not chained: %+v", d2)
	}
	d3 := e.seal(t) // nothing new: an empty digest still extends the chain
	if d3.Count != 0 || string(d3.PrevSignature) != string(d2.Signature) {
		t.Fatalf("empty digest %+v", d3)
	}
	if r := e.verify(t); !r.OK() {
		t.Fatalf("clean log failed verification: %v", r.Problems)
	}
}

func TestTamperedEventDetected(t *testing.T) {
	e := setup(t)
	e.record(t, 4)
	e.seal(t)
	su := storetest.Superuser(t, e.s)
	if _, err := su.Exec(context.Background(), `ALTER TABLE activities DISABLE TRIGGER USER;
		UPDATE activities SET event = jsonb_set(event, '{type}', '"tampered"') WHERE seq = (SELECT min(seq) FROM activities);
		ALTER TABLE activities ENABLE TRIGGER USER;`); err != nil {
		t.Fatal(err)
	}
	mustFail(t, e.verify(t), "hash mismatch")
}

func TestDeletedActivityDetected(t *testing.T) {
	e := setup(t)
	e.record(t, 4)
	e.seal(t)
	su := storetest.Superuser(t, e.s)
	if _, err := su.Exec(context.Background(), `ALTER TABLE activities DISABLE TRIGGER USER;
		DELETE FROM activities WHERE seq = (SELECT max(seq) FROM activities);
		ALTER TABLE activities ENABLE TRIGGER USER;`); err != nil {
		t.Fatal(err)
	}
	mustFail(t, e.verify(t), "count mismatch")
}

func TestRemovedDigestBreaksChain(t *testing.T) {
	e := setup(t)
	for i := 0; i < 3; i++ {
		e.record(t, 1)
		e.seal(t)
	}
	su := storetest.Superuser(t, e.s)
	if _, err := su.Exec(context.Background(), `ALTER TABLE activity_digests DISABLE TRIGGER USER;
		DELETE FROM activity_digests WHERE id = (SELECT id FROM activity_digests ORDER BY seq_to, sealed_at LIMIT 1 OFFSET 1);
		ALTER TABLE activity_digests ENABLE TRIGGER USER;`); err != nil {
		t.Fatal(err)
	}
	mustFail(t, e.verify(t), "chain broken")
}

func TestWrongKeyRejected(t *testing.T) {
	e := setup(t)
	e.record(t, 2)
	e.seal(t)
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	r, err := integrity.Verify(context.Background(), e.s, e.tenant, map[string]ed25519.PublicKey{e.signer.KeyID(): other})
	if err != nil {
		t.Fatal(err)
	}
	mustFail(t, r, "bad signature")
}

func TestUnsealedActivitiesReported(t *testing.T) {
	e := setup(t)
	e.record(t, 2)
	e.seal(t)
	e.record(t, 1) // after the last seal: not an error, but reported
	r := e.verify(t)
	if !r.OK() || r.Unsealed != 1 {
		t.Fatalf("report %+v, want OK with 1 unsealed", r)
	}
}

func TestLateArrivalBelowSealedRangeDetected(t *testing.T) {
	e := setup(t)
	e.record(t, 3)
	e.seal(t)
	// Simulate an activity that committed after its seq range was sealed.
	su := storetest.Superuser(t, e.s)
	if _, err := su.Exec(context.Background(), `INSERT INTO activities (id, seq, tenant_id, occurred_at, source, type, actor_type, actor_uid, operation, status_id, event)
		OVERRIDING SYSTEM VALUE
		SELECT uuidv7(), min(seq) - 1, tenant_id, now(), 'x', 'x', 'keel', 'x', 'x', 1, '{}' FROM activities GROUP BY tenant_id`); err != nil {
		t.Fatal(err)
	}
	mustFail(t, e.verify(t), "not covered")
}

func TestDigestsAreAppendOnlyForApp(t *testing.T) {
	e := setup(t)
	e.record(t, 1)
	e.seal(t)
	err := e.s.InTenant(context.Background(), e.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `DELETE FROM activity_digests`)
		return err
	})
	if err == nil {
		t.Fatal("app role deleted a digest")
	}
}

func TestSealAllCoversEveryTenant(t *testing.T) {
	e := setup(t)
	other, err := e.s.CreateTenant(t.Context(), "acme", "Acme", false)
	if err != nil {
		t.Fatal(err)
	}
	e.record(t, 2)
	e.clock = e.clock.Add(time.Second)
	if err := e.sealer.SealAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, tenant := range []string{e.tenant, other} {
		r, err := integrity.Verify(context.Background(), e.s, tenant, map[string]ed25519.PublicKey{e.signer.KeyID(): e.pub})
		if err != nil {
			t.Fatal(err)
		}
		if !r.OK() || r.Digests != 1 {
			t.Errorf("tenant %s: %+v, want one clean digest", tenant, r)
		}
	}
}
