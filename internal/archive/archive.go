// Package archive ships sealed Activity Log digests and the activities they
// cover to write-once object storage, and verifies that copy offline (#25,
// ADR-0005). Any S3-compatible store works: Tencent COS, AWS S3.
//
// Layout per Tenant, ordered by seq_to:
//
//	activity-log/v1/<tenant>/<seq_to:020d>-<digest id>.jsonl        one activity per line
//	activity-log/v1/<tenant>/<seq_to:020d>-<digest id>.digest.json  the signed digest
//
// Each line is {"seq":…,"id":…,"event":<event exactly as Postgres renders it>},
// so the batch hash can be recomputed without the database.
package archive

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/integrity"
	"github.com/hx-thanadej/keel/internal/store"
)

// ErrNotFound is returned by ObjectStore.Get for a missing key.
var ErrNotFound = errors.New("object not found")

// ObjectStore is the minimal object API the archive needs.
type ObjectStore interface {
	Put(ctx context.Context, key string, body []byte, contentType string) error
	Get(ctx context.Context, key string) ([]byte, error)
	List(ctx context.Context, prefix string) ([]string, error) // sorted
}

// Prefix is where a Tenant's archive lives.
func Prefix(tenantID string) string { return "activity-log/v1/" + tenantID + "/" }

// Exporter copies sealed, not-yet-exported digests to the archive.
type Exporter struct {
	Store   *store.Store
	Objects ObjectStore
}

// ExportAll exports every Tenant's pending digests, oldest first, and returns
// how many were exported. Each digest commits on its own, so a failure leaves
// earlier ones recorded.
func (e *Exporter) ExportAll(ctx context.Context) (int, error) {
	rows, err := e.Store.AppPool().Query(ctx, `SELECT t::text FROM tenant_ids() AS t`)
	if err != nil {
		return 0, err
	}
	tenants, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return 0, err
	}
	total := 0
	var errs []error
	for _, t := range tenants {
		n, err := e.exportTenant(ctx, t)
		total += n
		if err != nil {
			errs = append(errs, fmt.Errorf("tenant %s: %w", t, err))
		}
	}
	return total, errors.Join(errs...)
}

// line is one archived activity. Unmarshalling into json.RawMessage keeps the
// event's bytes exactly as written.
type line struct {
	Seq   int64           `json:"seq"`
	ID    string          `json:"id"`
	Event json.RawMessage `json:"event"`
}

func (e *Exporter) exportTenant(ctx context.Context, tenant string) (int, error) {
	n := 0
	for {
		done := false
		err := e.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
			var d integrity.Digest
			err := tx.QueryRow(ctx, `SELECT d.id::text, d.tenant_id::text, d.seq_from, d.seq_to, d.count, d.batch_sha256, d.cutoff, d.sealed_at, d.prev_signature, d.key_id, d.signature
				FROM activity_digests d LEFT JOIN activity_exports x ON x.digest_id = d.id
				WHERE x.digest_id IS NULL ORDER BY d.sealed_at, d.seq_to LIMIT 1`).
				Scan(&d.ID, &d.TenantID, &d.SeqFrom, &d.SeqTo, &d.Count, &d.BatchSHA256, &d.Cutoff, &d.SealedAt, &d.PrevSignature, &d.KeyID, &d.Signature)
			if errors.Is(err, pgx.ErrNoRows) {
				done = true
				return nil
			}
			if err != nil {
				return err
			}
			rows, err := tx.Query(ctx, `SELECT seq, id::text, event::text FROM activities WHERE seq > $1 AND seq <= $2 ORDER BY seq`, d.SeqFrom, d.SeqTo)
			if err != nil {
				return err
			}
			var buf bytes.Buffer
			for rows.Next() {
				var seq int64
				var id, ev string
				if err := rows.Scan(&seq, &id, &ev); err != nil {
					rows.Close()
					return err
				}
				// Written by hand: json.Marshal would compact and HTML-escape the
				// event, changing the bytes the digest hashed.
				fmt.Fprintf(&buf, "{\"seq\":%d,\"id\":%q,\"event\":%s}\n", seq, id, ev)
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				return err
			}
			base := fmt.Sprintf("%s%020d-%s", Prefix(tenant), d.SeqTo, d.ID)
			dataKey, digestKey := base+".jsonl", base+".digest.json"
			dj, _ := json.Marshal(d)
			// Data first: a digest object never points at missing data.
			if err := e.Objects.Put(ctx, dataKey, buf.Bytes(), "application/x-ndjson"); err != nil {
				return fmt.Errorf("put %s: %w", dataKey, err)
			}
			if err := e.Objects.Put(ctx, digestKey, dj, "application/json"); err != nil {
				return fmt.Errorf("put %s: %w", digestKey, err)
			}
			_, err = tx.Exec(ctx, `INSERT INTO activity_exports (digest_id, tenant_id, data_key, digest_key) VALUES ($1, $2, $3, $4)`, d.ID, tenant, dataKey, digestKey)
			return err
		})
		if err != nil || done {
			return n, err
		}
		n++
	}
}

// Verify checks a Tenant's archived chain without the database.
func Verify(ctx context.Context, objs ObjectStore, tenant string, keys map[string]ed25519.PublicKey) (integrity.Report, error) {
	var r integrity.Report
	all, err := objs.List(ctx, Prefix(tenant))
	if err != nil {
		return r, err
	}
	var digests []string
	for _, k := range all {
		if strings.HasSuffix(k, ".digest.json") {
			digests = append(digests, k)
		}
	}
	r.Digests = len(digests)
	var prev integrity.Digest
	for i, key := range digests {
		raw, err := objs.Get(ctx, key)
		if err != nil {
			return r, fmt.Errorf("get %s: %w", key, err)
		}
		var d integrity.Digest
		if err := json.Unmarshal(raw, &d); err != nil {
			r.Problems = append(r.Problems, key+": unreadable digest")
			continue
		}
		name := fmt.Sprintf("digest %d (seq %d..%d)", i+1, d.SeqFrom, d.SeqTo)
		if i == 0 && (d.PrevSignature != nil || d.SeqFrom != 0) {
			r.Problems = append(r.Problems, name+": chain broken: first archived digest does not start the chain")
		}
		if i > 0 && (!bytes.Equal(d.PrevSignature, prev.Signature) || d.SeqFrom != prev.SeqTo) {
			r.Problems = append(r.Problems, name+": chain broken: does not follow the previous digest")
		}
		pub, ok := keys[d.KeyID]
		if !ok || !ed25519.Verify(pub, d.Canonical(), d.Signature) {
			r.Problems = append(r.Problems, name+": bad signature (key "+d.KeyID+")")
		}
		data, err := objs.Get(ctx, strings.TrimSuffix(key, ".digest.json")+".jsonl")
		if errors.Is(err, ErrNotFound) {
			r.Problems = append(r.Problems, name+": data object missing")
			prev = d
			continue
		}
		if err != nil {
			return r, err
		}
		b := integrity.NewBatchHasher()
		sc := bufio.NewScanner(bytes.NewReader(data))
		sc.Buffer(make([]byte, 1<<20), 16<<20)
		for sc.Scan() {
			var l line
			if err := json.Unmarshal(sc.Bytes(), &l); err != nil {
				r.Problems = append(r.Problems, name+": unreadable line")
				continue
			}
			b.Add(l.Seq, l.ID, l.Event)
		}
		n, sum := b.Sum()
		switch {
		case n != d.Count:
			r.Problems = append(r.Problems, fmt.Sprintf("%s: count mismatch: digest says %d, archive has %d", name, d.Count, n))
		case !bytes.Equal(sum, d.BatchSHA256):
			r.Problems = append(r.Problems, name+": batch hash mismatch: an archived activity was altered")
		}
		r.Covered += n
		prev = d
	}
	return r, nil
}
