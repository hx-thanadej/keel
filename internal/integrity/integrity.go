// Package integrity makes the Activity Log tamper-evident (#24, ADR-0005).
//
// Each Tenant has its own chain of signed digests, so a Tenant can verify its
// own log without seeing anyone else's. Seal covers every activity logged
// before now−Grace that no earlier digest covers; an empty digest still
// extends the chain and proves the sealer was alive. Verify recomputes
// everything from the stored activities.
package integrity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/store"
)

// Signer signs digests. Ed25519 in-process today; a KMS-backed signer can
// implement the same interface.
type Signer interface {
	KeyID() string
	Sign(msg []byte) ([]byte, error)
}

// Ed25519 is an in-process Signer.
type Ed25519 struct{ priv ed25519.PrivateKey }

// NewEd25519 wraps a private key.
func NewEd25519(priv ed25519.PrivateKey) *Ed25519 { return &Ed25519{priv: priv} }

// KeyID is the first 8 bytes of SHA-256 of the public key, hex.
func (e *Ed25519) KeyID() string { return KeyID(e.priv.Public().(ed25519.PublicKey)) }

// Sign implements Signer.
func (e *Ed25519) Sign(msg []byte) ([]byte, error) { return ed25519.Sign(e.priv, msg), nil }

// KeyID derives a key id from a public key.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// Digest is one link in a Tenant's chain.
type Digest struct {
	ID            string
	TenantID      string
	SeqFrom       int64 // exclusive
	SeqTo         int64 // inclusive
	Count         int
	BatchSHA256   []byte
	Cutoff        time.Time
	SealedAt      time.Time
	PrevSignature []byte
	KeyID         string
	Signature     []byte
}

// Canonical is the exact byte string that is signed.
func (d Digest) Canonical() []byte {
	return fmt.Appendf(nil, "keel-activity-digest/v1\ntenant=%s\nseq_from=%d\nseq_to=%d\ncount=%d\nbatch_sha256=%x\ncutoff=%s\nprev_signature=%x\nkey_id=%s\n",
		d.TenantID, d.SeqFrom, d.SeqTo, d.Count, d.BatchSHA256, d.Cutoff.UTC().Format(time.RFC3339Nano), d.PrevSignature, d.KeyID)
}

// Sealer appends digests.
type Sealer struct {
	Store  *store.Store
	Signer Signer
	// Grace excludes activities logged in the last Grace, so transactions
	// still committing are sealed next time. Must exceed the longest app
	// transaction. Default 5m.
	Grace time.Duration
	Now   func() time.Time
}

const digestCols = `id::text, tenant_id::text, seq_from, seq_to, count, batch_sha256, cutoff, sealed_at, prev_signature, key_id, signature`

func scanDigest(r pgx.Row) (Digest, error) {
	var d Digest
	err := r.Scan(&d.ID, &d.TenantID, &d.SeqFrom, &d.SeqTo, &d.Count, &d.BatchSHA256, &d.Cutoff, &d.SealedAt, &d.PrevSignature, &d.KeyID, &d.Signature)
	return d, err
}

// BatchHasher computes a digest's batch hash. Feed activities in seq order;
// event is the activity's event exactly as Postgres renders event::text.
// The database verifier and the offline archive verifier both use it.
type BatchHasher struct {
	h hash.Hash
	n int
}

// NewBatchHasher starts an empty batch.
func NewBatchHasher() *BatchHasher { return &BatchHasher{h: sha256.New()} }

// Add appends one activity.
func (b *BatchHasher) Add(seq int64, id string, event []byte) {
	sum := sha256.Sum256(event)
	_, _ = fmt.Fprintf(b.h, "%d %s %x\n", seq, id, sum) // hash writes cannot fail
	b.n++
}

// Sum returns the count and hash so far.
func (b *BatchHasher) Sum() (int, []byte) { return b.n, b.h.Sum(nil) }

// batch hashes activities seq_from < seq <= seq_to of the scoped Tenant.
func batch(ctx context.Context, tx pgx.Tx, from, to int64) (int, []byte, error) {
	rows, err := tx.Query(ctx, `SELECT seq, id::text, convert_to(event::text, 'UTF8') FROM activities WHERE seq > $1 AND seq <= $2 ORDER BY seq`, from, to)
	if err != nil {
		return 0, nil, err
	}
	defer rows.Close()
	b := NewBatchHasher()
	for rows.Next() {
		var seq int64
		var id string
		var ev []byte
		if err := rows.Scan(&seq, &id, &ev); err != nil {
			return 0, nil, err
		}
		b.Add(seq, id, ev)
	}
	n, sum := b.Sum()
	return n, sum, rows.Err()
}

// Seal appends the next digest for tenantID.
func (s *Sealer) Seal(ctx context.Context, tenantID string) (Digest, error) {
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	grace := s.Grace
	if grace == 0 {
		grace = 5 * time.Minute
	}
	var d Digest
	err := s.Store.InTenant(ctx, tenantID, func(tx pgx.Tx) error {
		// One sealer per Tenant at a time.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('keel.seal.' || $1))`, tenantID); err != nil {
			return err
		}
		prev, err := scanDigest(tx.QueryRow(ctx, `SELECT `+digestCols+` FROM activity_digests ORDER BY sealed_at DESC, seq_to DESC LIMIT 1`))
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		// Postgres keeps microseconds; truncate so the signed bytes survive a round trip.
		t := now().Truncate(time.Microsecond)
		d = Digest{TenantID: tenantID, SeqFrom: prev.SeqTo, PrevSignature: prev.Signature, KeyID: s.Signer.KeyID(),
			Cutoff: t.Add(-grace).Truncate(time.Microsecond), SealedAt: t}
		if err := tx.QueryRow(ctx, `SELECT coalesce(max(seq), $1) FROM activities WHERE seq > $1 AND logged_at < $2`, d.SeqFrom, d.Cutoff).Scan(&d.SeqTo); err != nil {
			return err
		}
		if d.Count, d.BatchSHA256, err = batch(ctx, tx, d.SeqFrom, d.SeqTo); err != nil {
			return err
		}
		if d.Signature, err = s.Signer.Sign(d.Canonical()); err != nil {
			return fmt.Errorf("sign digest: %w", err)
		}
		return tx.QueryRow(ctx, `INSERT INTO activity_digests (tenant_id, seq_from, seq_to, count, batch_sha256, cutoff, sealed_at, prev_signature, key_id, signature)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id::text`,
			d.TenantID, d.SeqFrom, d.SeqTo, d.Count, d.BatchSHA256, d.Cutoff, d.SealedAt, d.PrevSignature, d.KeyID, d.Signature).Scan(&d.ID)
	})
	return d, err
}

// SealAll seals every Tenant; errors are collected, not fatal.
func (s *Sealer) SealAll(ctx context.Context) error {
	rows, err := s.Store.AppPool().Query(ctx, `SELECT t::text FROM tenant_ids() AS t`)
	if err != nil {
		return err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	var errs []error
	for _, id := range ids {
		if _, err := s.Seal(ctx, id); err != nil {
			errs = append(errs, fmt.Errorf("tenant %s: %w", id, err))
		}
	}
	return errors.Join(errs...)
}

// Report is the outcome of Verify.
type Report struct {
	Digests  int
	Covered  int      // activities covered by digests
	Unsealed int      // activities after the last digest (normal; sealed next run)
	Problems []string // any entry means the log cannot be trusted
}

// OK reports whether verification found no problems.
func (r Report) OK() bool { return len(r.Problems) == 0 }

// Verify checks tenantID's chain against keys (key id → public key).
func Verify(ctx context.Context, s *store.Store, tenantID string, keys map[string]ed25519.PublicKey) (Report, error) {
	var r Report
	err := s.InTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+digestCols+` FROM activity_digests ORDER BY sealed_at, seq_to`)
		if err != nil {
			return err
		}
		digests, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Digest, error) { return scanDigest(row) })
		if err != nil {
			return err
		}
		r.Digests = len(digests)
		var prev Digest
		for i, d := range digests {
			name := fmt.Sprintf("digest %d (seq %d..%d)", i+1, d.SeqFrom, d.SeqTo)
			if i == 0 && (d.PrevSignature != nil || d.SeqFrom != 0) {
				r.Problems = append(r.Problems, name+": chain broken: first digest does not start the chain")
			}
			if i > 0 && (!bytes.Equal(d.PrevSignature, prev.Signature) || d.SeqFrom != prev.SeqTo) {
				r.Problems = append(r.Problems, name+": chain broken: does not follow the previous digest")
			}
			pub, ok := keys[d.KeyID]
			if !ok || !ed25519.Verify(pub, d.Canonical(), d.Signature) {
				r.Problems = append(r.Problems, name+": bad signature (key "+d.KeyID+")")
			}
			n, sum, err := batch(ctx, tx, d.SeqFrom, d.SeqTo)
			if err != nil {
				return err
			}
			if n != d.Count {
				r.Problems = append(r.Problems, fmt.Sprintf("%s: count mismatch: digest says %d, log has %d", name, d.Count, n))
			} else if !bytes.Equal(sum, d.BatchSHA256) {
				r.Problems = append(r.Problems, name+": batch hash mismatch: an activity was altered")
			}
			r.Covered += n
			prev = d
		}
		var total, after int
		if err := tx.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE seq > $1) FROM activities`, prev.SeqTo).Scan(&total, &after); err != nil {
			return err
		}
		r.Unsealed = after
		if missing := total - after - r.Covered; missing != 0 {
			r.Problems = append(r.Problems, fmt.Sprintf("%d activities not covered by any digest despite falling inside the sealed range", missing))
		}
		return nil
	})
	return r, err
}
