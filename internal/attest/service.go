package attest

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/store"
)

var (
	ErrNotFound = errors.New("release not found")
	ErrInvalid  = errors.New("invalid")
)

// Attestation is one verified submission.
type Attestation struct {
	ID          string    `json:"id"`
	ReleaseID   string    `json:"release_id"`
	ImageDigest string    `json:"image_digest"`
	Passed      bool      `json:"passed"`
	Checks      []Check   `json:"checks"`
	VSA         Envelope  `json:"vsa"`
	SubmittedBy string    `json:"submitted_by"`
	CreatedAt   time.Time `json:"created_at"`
}

// Service verifies provenance for Releases.
type Service struct {
	Store       *store.Store
	Verifier    Verifier
	Key         ed25519.PrivateKey
	VerifierID  string // e.g. https://keel.example.com/attestations
	Expectation Expectation
	Now         func() time.Time
}

// Submit verifies a bundle against every image of the Release it attests
// to, records the checks and a signed VSA per image, and returns them.
// A bundle that fails is still recorded, so the reason is visible.
func (s Service) Submit(ctx context.Context, tenant, release string, bundle []byte, by activity.Actor) ([]Attestation, error) {
	if s.Verifier == nil || s.Key == nil {
		return nil, errors.New("release verification is not configured (KEEL_SIGSTORE_TRUSTED_ROOT, KEEL_DIGEST_KEY)")
	}
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	var images []struct{ Name, Digest string }
	var repoID *int64
	if err := s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		var raw []byte
		err := tx.QueryRow(ctx, `SELECT r.images, s.repository_id FROM releases r JOIN services s ON s.id = r.service_id WHERE r.id = $1`, release).Scan(&raw, &repoID)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		return json.Unmarshal(raw, &images)
	}); err != nil {
		return nil, err
	}
	exp := s.Expectation
	if repoID != nil {
		exp.RepositoryID = strconv.FormatInt(*repoID, 10)
	}
	sum := sha256.Sum256(bundle)
	bundleSHA := hex.EncodeToString(sum[:])
	var out []Attestation
	var lastErr error
	for _, img := range images {
		ev, err := s.Verifier.Verify(bundle, img.Digest)
		if err != nil {
			lastErr = err
			continue // this bundle is not about this image
		}
		checks := Evaluate(ev, exp, img.Digest)
		vsa, err := VSA(s.Key, s.VerifierID, "release:"+release, img.Name, img.Digest, checks, bundleSHA, now())
		if err != nil {
			return nil, err
		}
		a := Attestation{ReleaseID: release, ImageDigest: img.Digest, Passed: Passed(checks), Checks: checks, VSA: vsa, SubmittedBy: by.UID}
		err = s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
			cj, _ := json.Marshal(checks)
			cert, _ := json.Marshal(ev.Certificate)
			vj, _ := json.Marshal(vsa)
			if err := tx.QueryRow(ctx, `INSERT INTO release_attestations (tenant_id, release_id, image_digest, passed, checks, certificate, bundle_sha256, vsa, submitted_by)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id::text, created_at`, tenant, release, img.Digest, a.Passed, cj, cert, bundleSHA, vj, by.UID).Scan(&a.ID, &a.CreatedAt); err != nil {
				return err
			}
			outcome, detail := activity.Success, fmt.Sprintf("%s %s: PASSED (%s)", img.Name, img.Digest[:19], PolicyVersion)
			if !a.Passed {
				outcome = activity.Failure
				detail = fmt.Sprintf("%s %s: FAILED %s (%s)", img.Name, img.Digest[:19], failed(checks), PolicyVersion)
			}
			_, err := activity.Record(ctx, tx, activity.Activity{TenantID: tenant, Source: "keel/attest", Type: "keel.release.verified", Subject: "release/" + release,
				Operation: "VerifyProvenance", Kind: activity.Create, Actor: by, Outcome: outcome, StatusDetail: detail,
				Resources: []activity.Resource{{Type: "release", UID: release}, {Type: "attestation", UID: a.ID}}})
			return err
		})
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: the bundle does not verify for any image of this release: %v", ErrInvalid, lastErr)
	}
	return out, nil
}

func failed(cs []Check) string {
	var names []string
	for _, c := range cs {
		if !c.Pass {
			names = append(names, c.Name)
		}
	}
	return fmt.Sprint(names)
}

// ReleaseService returns the Service a Release belongs to (for authorisation).
func (s Service) ReleaseService(ctx context.Context, tenant, release string) (string, error) {
	var svc string
	err := s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT service_id::text FROM releases WHERE id = $1`, release).Scan(&svc)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	return svc, err
}

// List returns a Release's attestations, newest first.
func (s Service) List(ctx context.Context, tenant, release string) ([]Attestation, error) {
	var out []Attestation
	err := s.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id::text, release_id::text, image_digest, passed, checks, vsa, submitted_by, created_at FROM release_attestations
			WHERE release_id = $1 ORDER BY created_at DESC`, release)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (Attestation, error) {
			var a Attestation
			var cj, vj []byte
			err := r.Scan(&a.ID, &a.ReleaseID, &a.ImageDigest, &a.Passed, &cj, &vj, &a.SubmittedBy, &a.CreatedAt)
			_ = json.Unmarshal(cj, &a.Checks)
			_ = json.Unmarshal(vj, &a.VSA)
			return a, err
		})
		return err
	})
	return out, err
}
