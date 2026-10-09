// Package evidence exports a Tenant's compliance evidence for a period
// (#151): Controls coverage, provenance verifications and SBOMs per Release,
// Finding SLA statistics, Exceptions, Access Grants, the Activity digest
// chain head and the PDPA section (#190), in one bundle whose manifest is
// signed with Keel's key so an auditor can check it offline. It also runs the EU CRA reporting clock for
// actively exploited vulnerabilities in deployed software.
package evidence

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/controls"
	"github.com/hx-thanadej/keel/internal/pdpa"
	"github.com/hx-thanadej/keel/internal/store"
)

// Bundle is the export.
type Bundle struct {
	Manifest  Manifest                   `json:"manifest"`
	Sections  map[string]json.RawMessage `json:"sections"`
	KeyID     string                     `json:"key_id"`
	Signature string                     `json:"signature"` // base64 Ed25519 over the manifest JSON
}

// Manifest names the bundle and hashes each section.
type Manifest struct {
	Format      string            `json:"format"`
	Tenant      string            `json:"tenant"`
	From        time.Time         `json:"from"`
	To          time.Time         `json:"to"`
	GeneratedAt time.Time         `json:"generated_at"`
	Controls    string            `json:"controls_version"`
	Sections    map[string]string `json:"sections"` // name → sha256 hex
}

// Format names this bundle layout.
const Format = "keel-evidence@1"

// Exporter builds bundles.
type Exporter struct {
	Store    *store.Store
	Controls controls.Service
	PDPA     pdpa.Service
	Key      ed25519.PrivateKey
	Now      func() time.Time
}

var ErrNoKey = errors.New("evidence export needs KEEL_DIGEST_KEY")

// Export builds and signs the bundle for [from, to).
func (e Exporter) Export(ctx context.Context, tenant string, from, to time.Time, by activity.Actor) (Bundle, error) {
	if e.Key == nil {
		return Bundle{}, ErrNoKey
	}
	now := time.Now
	if e.Now != nil {
		now = e.Now
	}
	sections := map[string]any{}
	rep, err := e.Controls.Report(ctx, tenant)
	if err != nil {
		return Bundle{}, err
	}
	sections["controls"] = rep
	err = e.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		q := func(name, sql string, args ...any) error {
			var raw []byte
			if err := tx.QueryRow(ctx, sql, args...).Scan(&raw); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			sections[name] = json.RawMessage(raw)
			return nil
		}
		if err := q("releases", `SELECT coalesce(jsonb_agg(x ORDER BY x->>'created_at'), '[]') FROM (
			SELECT jsonb_build_object('release', r.id, 'service', s.slug, 'version', r.version, 'created_at', r.created_at, 'images', r.images,
				'verified', release_verified(r.id),
				'attestations', (SELECT coalesce(jsonb_agg(jsonb_build_object('digest', a.image_digest, 'passed', a.passed, 'checks', a.checks, 'vsa', a.vsa, 'at', a.created_at)), '[]') FROM release_attestations a WHERE a.release_id = r.id),
				'sboms', (SELECT coalesce(jsonb_agg(jsonb_build_object('format', b.format, 'spec_version', b.spec_version, 'tool', b.tool, 'components', b.components, 'gaps', b.gaps)), '[]') FROM release_sboms b WHERE b.release_id = r.id),
				'deployments', (SELECT coalesce(jsonb_agg(jsonb_build_object('environment', e.name, 'deployed_at', p.deployed_at, 'failed_at', p.failed_at)), '[]') FROM promotions p JOIN environments e ON e.id = p.environment_id WHERE p.release_id = r.id AND p.state = 'deployed')
			) AS x FROM releases r JOIN services s ON s.id = r.service_id WHERE r.created_at >= $1 AND r.created_at < $2) q`, from, to); err != nil {
			return err
		}
		if err := q("findings", `SELECT jsonb_build_object(
				'open_by_severity', (SELECT coalesce(jsonb_object_agg(severity, n), '{}') FROM (SELECT severity, count(*) n FROM findings WHERE status = 'open' GROUP BY severity) a),
				'overdue', (SELECT count(*) FROM findings WHERE status = 'open' AND due_at < $2),
				'resolved_in_period', (SELECT count(*) FROM findings WHERE resolved_at >= $1 AND resolved_at < $2),
				'resolved_within_sla', (SELECT count(*) FROM findings WHERE resolved_at >= $1 AND resolved_at < $2 AND (due_at IS NULL OR resolved_at <= due_at)),
				'raised_in_period', (SELECT count(*) FROM findings WHERE first_seen_at >= $1 AND first_seen_at < $2))`, from, to); err != nil {
			return err
		}
		if err := q("exceptions", `SELECT coalesce(jsonb_agg(jsonb_build_object('id', id, 'fingerprint', fingerprint, 'finding_ids', finding_ids, 'reason', reason, 'state', state,
				'requested_by', requested_by, 'decided_by', decided_by, 'expires_at', expires_at) ORDER BY created_at), '[]') FROM exceptions WHERE created_at < $2 AND (expires_at >= $1)`, from, to); err != nil {
			return err
		}
		if err := q("access_grants", `SELECT coalesce(jsonb_agg(jsonb_build_object('id', g.id, 'template', r.template, 'requester', g.requester, 'hours', g.hours, 'state', g.state,
				'approvals', g.approvals, 'activated_at', g.activated_at, 'ended_at', g.ended_at, 'reason', g.reason) ORDER BY g.created_at), '[]')
			FROM access_grants g JOIN access_roles r ON r.id = g.role_id WHERE g.created_at >= $1 AND g.created_at < $2`, from, to); err != nil {
			return err
		}
		ev, err := e.PDPA.Evidence(ctx, tx, e.Controls.Registry, from, to)
		if err != nil {
			return fmt.Errorf("pdpa: %w", err)
		}
		sections["pdpa"] = ev
		return q("activity_chain", `SELECT coalesce((SELECT jsonb_build_object('seq_to', seq_to, 'sealed_at', sealed_at, 'key_id', key_id, 'signature', encode(signature, 'base64'))
			FROM activity_digests ORDER BY sealed_at DESC LIMIT 1), '{"note": "no sealed digest yet"}')`)
	})
	if err != nil {
		return Bundle{}, err
	}
	b := Bundle{Sections: map[string]json.RawMessage{}, Manifest: Manifest{Format: Format, Tenant: tenant, From: from, To: to, GeneratedAt: now().UTC(),
		Controls: rep.Version, Sections: map[string]string{}}}
	names := make([]string, 0, len(sections))
	for n := range sections {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		raw, err := json.Marshal(sections[n])
		if err != nil {
			return Bundle{}, err
		}
		sum := sha256.Sum256(raw)
		b.Sections[n] = raw
		b.Manifest.Sections[n] = hex.EncodeToString(sum[:])
	}
	m, _ := json.Marshal(b.Manifest)
	pub := e.Key.Public().(ed25519.PublicKey)
	ks := sha256.Sum256(pub)
	b.KeyID = "keel:" + hex.EncodeToString(ks[:8])
	b.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(e.Key, m))
	return b, e.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		_, err := activity.Record(ctx, tx, activity.Activity{TenantID: tenant, Source: "keel/evidence", Type: "keel.evidence.exported", Subject: "tenant/" + tenant,
			Operation: "ExportEvidence", Kind: activity.Read, Actor: by, Outcome: activity.Success,
			StatusDetail: fmt.Sprintf("%s %s → %s, %d sections", Format, from.Format("2006-01-02"), to.Format("2006-01-02"), len(names))})
		return err
	})
}

// Verify checks a bundle offline: the signature over the manifest and every
// section's hash.
func Verify(pub ed25519.PublicKey, b Bundle) error {
	m, err := json.Marshal(b.Manifest)
	if err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(b.Signature)
	if err != nil || !ed25519.Verify(pub, m, sig) {
		return errors.New("manifest signature does not verify")
	}
	for name, want := range b.Manifest.Sections {
		raw, ok := b.Sections[name]
		if !ok {
			return fmt.Errorf("section %s missing", name)
		}
		var v any
		if err := json.Unmarshal(raw, &v); err != nil {
			return err
		}
		canon, _ := json.Marshal(v)
		sum := sha256.Sum256(canon)
		if hex.EncodeToString(sum[:]) != want {
			// Sections are hashed as Keel serialised them; re-serialising
			// may reorder keys, so compare the raw bytes too.
			raw2 := sha256.Sum256(raw)
			if hex.EncodeToString(raw2[:]) != want {
				return fmt.Errorf("section %s was altered", name)
			}
		}
	}
	if len(b.Sections) != len(b.Manifest.Sections) {
		return errors.New("bundle has sections the manifest does not list")
	}
	return nil
}
