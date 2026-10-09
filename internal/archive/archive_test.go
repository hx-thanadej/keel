package archive_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/archive"
	"github.com/hx-thanadej/keel/internal/integrity"
	"github.com/hx-thanadej/keel/internal/store"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

// memStore is an in-memory ObjectStore.
type memStore struct {
	mu   sync.Mutex
	objs map[string][]byte
	puts int
}

func newMem() *memStore { return &memStore{objs: map[string][]byte{}} }

func (m *memStore) Put(_ context.Context, key string, body []byte, _ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.objs[key] = bytes.Clone(body)
	m.puts++
	return nil
}

func (m *memStore) Get(_ context.Context, key string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.objs[key]
	if !ok {
		return nil, archive.ErrNotFound
	}
	return bytes.Clone(b), nil
}

func (m *memStore) List(_ context.Context, prefix string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for k := range m.objs {
		if strings.HasPrefix(k, prefix) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out, nil
}

type fixture struct {
	s      *store.Store
	tenant string
	sealer *integrity.Sealer
	keys   map[string]ed25519.PublicKey
	clock  time.Time
}

func setup(t *testing.T) *fixture {
	t.Helper()
	s := storetest.New(t)
	tenant, err := s.CreateTenant(t.Context(), "tat", "TAT", false)
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer := integrity.NewEd25519(priv)
	f := &fixture{s: s, tenant: tenant, keys: map[string]ed25519.PublicKey{signer.KeyID(): pub}, clock: time.Now()}
	f.sealer = &integrity.Sealer{Store: s, Signer: signer, Grace: time.Nanosecond, Now: func() time.Time { return f.clock }}
	return f
}

func (f *fixture) recordAndSeal(t *testing.T, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		err := f.s.InTenant(context.Background(), f.tenant, func(tx pgx.Tx) error {
			_, err := activity.Record(context.Background(), tx, activity.Activity{
				TenantID: f.tenant, Source: "test", Type: "test.event", Operation: "Test", Kind: activity.Create,
				Actor: activity.Actor{Type: activity.ActorKeel, UID: "keel:test"}, Outcome: activity.Success,
				Why: activity.Why{Reason: "unicode ✓ and \"quotes\""},
			})
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	f.clock = f.clock.Add(time.Second)
	if _, err := f.sealer.Seal(context.Background(), f.tenant); err != nil {
		t.Fatal(err)
	}
}

func TestExportThenVerifyOffline(t *testing.T) {
	f := setup(t)
	objs := newMem()
	ex := &archive.Exporter{Store: f.s, Objects: objs}
	f.recordAndSeal(t, 3)
	f.recordAndSeal(t, 2)
	f.recordAndSeal(t, 0)

	n, err := ex.ExportAll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("exported %d digests, want 3", n)
	}
	if objs.puts != 6 {
		t.Fatalf("puts = %d, want 6 (data + digest per digest)", objs.puts)
	}
	// Idempotent.
	if n, _ := ex.ExportAll(context.Background()); n != 0 || objs.puts != 6 {
		t.Fatalf("re-export wrote again: n=%d puts=%d", n, objs.puts)
	}

	rep, err := archive.Verify(context.Background(), objs, f.tenant, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK() || rep.Digests != 3 || rep.Covered != 5 {
		t.Fatalf("offline verify %+v", rep)
	}
}

func TestOfflineVerifyCatchesTamperedArchive(t *testing.T) {
	f := setup(t)
	objs := newMem()
	ex := &archive.Exporter{Store: f.s, Objects: objs}
	f.recordAndSeal(t, 2)
	f.recordAndSeal(t, 2)
	if _, err := ex.ExportAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	keys, _ := objs.List(context.Background(), "")
	var data, digest []string
	for _, k := range keys {
		if strings.HasSuffix(k, ".jsonl") {
			data = append(data, k)
		} else {
			digest = append(digest, k)
		}
	}

	cases := map[string]func(){
		"edited event": func() {
			b, _ := objs.Get(context.Background(), data[0])
			_ = objs.Put(context.Background(), data[0], bytes.Replace(b, []byte("test.event"), []byte("evil.event"), 1), "")
		},
		"dropped line": func() {
			b, _ := objs.Get(context.Background(), data[1])
			lines := bytes.SplitAfter(b, []byte("\n"))
			_ = objs.Put(context.Background(), data[1], bytes.Join(lines[1:], nil), "")
		},
		"deleted digest": func() {
			objs.mu.Lock()
			delete(objs.objs, digest[0])
			objs.mu.Unlock()
		},
	}
	want := map[string]string{"edited event": "hash mismatch", "dropped line": "count mismatch", "deleted digest": "chain broken"}
	for name, tamper := range cases {
		snapshot := map[string][]byte{}
		for k, v := range objs.objs {
			snapshot[k] = v
		}
		tamper()
		rep, err := archive.Verify(context.Background(), objs, f.tenant, f.keys)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if rep.OK() || !strings.Contains(strings.Join(rep.Problems, "\n"), want[name]) {
			t.Errorf("%s: problems %v, want %q", name, rep.Problems, want[name])
		}
		objs.objs = snapshot
	}
}
