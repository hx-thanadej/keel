// Package evidence exports a Tenant's compliance evidence for a period
// (#151, #191) as a keel-evidence@2 bundle: one section per framework that
// lists every Control with the Keel Policies covering it, the evidence in the
// period and the gap with its reason, plus the evidence sections those
// Controls point at (Releases with provenance and SBOMs, Finding SLA
// statistics, Exceptions, Access Grants, PDPA retention and breaches, the
// Activity digest chain head). The manifest hashes every section and is
// signed with Keel's key so an auditor can check it offline. The package also
// runs the EU CRA reporting clock for actively exploited vulnerabilities in
// deployed software.
package evidence

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

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

// Manifest names the bundle and hashes each section. Frameworks is empty in
// keel-evidence@1 bundles, so their manifests serialise as they were signed.
type Manifest struct {
	Format      string            `json:"format"`
	Tenant      string            `json:"tenant"`
	From        time.Time         `json:"from"`
	To          time.Time         `json:"to"`
	GeneratedAt time.Time         `json:"generated_at"`
	Controls    string            `json:"controls_version"`
	Sections    map[string]string `json:"sections"` // name → sha256 hex
	Frameworks  []string          `json:"frameworks,omitempty"`
}

// Format names this bundle layout. FormatV1 bundles, with one controls
// section instead of one section per framework, still verify.
const (
	Format   = "keel-evidence@2"
	FormatV1 = "keel-evidence@1"
)

// FrameworkSection is the "frameworks/<id>" section: a framework's coverage
// counts and every one of its Controls.
type FrameworkSection struct {
	Coverage controls.FrameworkCoverage `json:"coverage"`
	Services int                        `json:"services"`
	Controls []ControlSection           `json:"controls"`
}

// ControlSection is one Control: its Policies with the Services each
// evaluated, the bundle sections holding its evidence, and its gap reason
// when no Policy reached a Service.
type ControlSection struct {
	controls.ControlView
	Evidence []Ref `json:"evidence"`
}

// Ref points at a bundle section, or a field of one ("pdpa.breaches"). Items
// counts its entries in the period when it is a list.
type Ref struct {
	Section string `json:"section"`
	Items   *int   `json:"items,omitempty"`
}

// policyEvidence names the sections that hold each Policy's evidence in the
// period. A Policy with none is evidenced by the Services it covers.
var policyEvidence = map[string][]string{
	"keel-authz@1":          nil,
	"keel-access@1":         {"access_grants"},
	"keel-github@1":         nil,
	"keel-scans@1":          {"findings"},
	"keel-release@1":        {"releases"},
	"keel-sbom@1":           {"releases"},
	"keel-promotion@1":      {"releases"},
	"keel-admission@1":      nil,
	"keel-baseline@1":       nil,
	"keel-ci-identity@1":    nil,
	"keel-findings@1":       {"findings", "exceptions"},
	"keel-vex@1":            nil,
	"keel-activity@1":       {"activity_chain"},
	"keel-pdpa-residency@1": {"pdpa.residency", "pdpa.residency_coverage"},
	"keel-pdpa-retention@1": {"pdpa.retention_schedule", "pdpa.retention_runs"},
	"keel-pdpa-breach@1":    {"pdpa.breaches"},
}

const noServiceGap = "its Policies have evaluated no Service yet"

// Exporter builds bundles.
type Exporter struct {
	Store    *store.Store
	Controls controls.Service
	PDPA     pdpa.Service
	Key      ed25519.PrivateKey
	Now      func() time.Time
}

var (
	ErrNoKey            = errors.New("evidence export needs KEEL_DIGEST_KEY")
	ErrUnknownFramework = errors.New("unknown framework")
)

// Export builds and signs the bundle for [from, to), for one framework
// (matched without case) or, when framework is empty, for all of them.
func (e Exporter) Export(ctx context.Context, tenant, framework string, from, to time.Time, by activity.Actor) (Bundle, error) {
	if e.Key == nil {
		return Bundle{}, ErrNoKey
	}
	now := time.Now
	if e.Now != nil {
		now = e.Now
	}
	rep, err := e.Controls.Report(ctx, tenant)
	if err != nil {
		return Bundle{}, err
	}
	if framework != "" {
		var ok bool
		if rep, ok = rep.Only(framework); !ok {
			return Bundle{}, fmt.Errorf("%w %q", ErrUnknownFramework, framework)
		}
	}
	data := map[string]json.RawMessage{}
	err = e.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		q := func(name, sql string, args ...any) error {
			var raw []byte
			if err := tx.QueryRow(ctx, sql, args...).Scan(&raw); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			data[name] = raw
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
		ev, err := e.PDPA.Evidence(ctx, tx, from, to)
		if err != nil {
			return fmt.Errorf("pdpa: %w", err)
		}
		if data["pdpa"], err = json.Marshal(ev); err != nil {
			return err
		}
		return q("activity_chain", `SELECT coalesce((SELECT jsonb_build_object('seq_to', seq_to, 'sealed_at', sealed_at, 'key_id', key_id, 'signature', encode(signature, 'base64'))
			FROM activity_digests ORDER BY sealed_at DESC LIMIT 1), '{"note": "no sealed digest yet"}')`)
	})
	if err != nil {
		return Bundle{}, err
	}
	sections, err := frameworkSections(rep, data)
	if err != nil {
		return Bundle{}, err
	}
	b := Bundle{Sections: map[string]json.RawMessage{}, Manifest: Manifest{Format: Format, Tenant: tenant, From: from, To: to, GeneratedAt: now().UTC(),
		Controls: rep.Version, Sections: map[string]string{}}}
	for _, f := range rep.Frameworks {
		b.Manifest.Frameworks = append(b.Manifest.Frameworks, f.ID)
	}
	names := make([]string, 0, len(sections))
	for n := range sections {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		raw, err := canonical(sections[n])
		if err != nil {
			return Bundle{}, fmt.Errorf("section %s: %w", n, err)
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
			StatusDetail: fmt.Sprintf("%s %s %s → %s, %d sections", Format, strings.Join(b.Manifest.Frameworks, ","), from.Format("2006-01-02"), to.Format("2006-01-02"), len(names))})
		return err
	})
}

// frameworkSections lays out one section per framework in rep and the
// evidence sections their Controls point at; data the selected frameworks do
// not reference stays out of the bundle.
func frameworkSections(rep controls.Report, data map[string]json.RawMessage) (map[string]any, error) {
	sections := map[string]any{}
	byFramework := map[string]*FrameworkSection{}
	for _, f := range rep.Frameworks {
		fs := &FrameworkSection{Coverage: f, Services: rep.Services, Controls: []ControlSection{}}
		byFramework[f.ID] = fs
		sections["frameworks/"+f.ID] = fs
	}
	for _, c := range rep.Controls {
		cs := ControlSection{ControlView: c, Evidence: []Ref{}}
		if c.Gap && c.GapReason == "" {
			cs.GapReason = noServiceGap
		}
		seen := map[string]bool{}
		for _, p := range c.CoveredBy {
			refs, ok := policyEvidence[p]
			if !ok {
				return nil, fmt.Errorf("policy %s names no evidence sections", p)
			}
			for _, ref := range refs {
				if seen[ref] {
					continue
				}
				seen[ref] = true
				top, _, _ := strings.Cut(ref, ".")
				raw, ok := data[top]
				if !ok {
					return nil, fmt.Errorf("policy %s names missing section %s", p, ref)
				}
				items, err := count(raw, ref)
				if err != nil {
					return nil, err
				}
				sections[top] = raw
				cs.Evidence = append(cs.Evidence, Ref{Section: ref, Items: items})
			}
		}
		fs := byFramework[c.Framework]
		fs.Controls = append(fs.Controls, cs)
	}
	return sections, nil
}

// count returns the number of entries at ref ("section" or
// "section.field") when it is a list.
func count(raw json.RawMessage, ref string) (*int, error) {
	_, field, nested := strings.Cut(ref, ".")
	if nested {
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(raw, &obj); err != nil {
			return nil, fmt.Errorf("section %s: %w", ref, err)
		}
		raw = obj[field]
	}
	var list []json.RawMessage
	if json.Unmarshal(raw, &list) != nil || list == nil {
		return nil, nil
	}
	n := len(list)
	return &n, nil
}

// canonical serialises v with object keys sorted, so a section re-encoded by
// any JSON tool hashes the same.
func canonical(v any) (json.RawMessage, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var generic any
	if err := dec.Decode(&generic); err != nil {
		return nil, err
	}
	return json.Marshal(generic)
}

const (
	// MaxBundleBytes bounds the input Verify accepts, so an offline check
	// never holds an unbounded file in memory.
	MaxBundleBytes = 64 << 20
	// MaxJSONDepth bounds nesting in the strict parser, which recurses once
	// per level. Genuine bundles nest under 10 levels deep.
	MaxJSONDepth = 128
)

// Verify checks bundle bytes offline and returns the bundle they hold: strict
// JSON (see strictJSON), no fields beyond Bundle's and Manifest's, a known
// format, the signature over the manifest and every section's hash.
// keel-evidence@1 bundles hashed sections as Keel serialised them, so the raw
// bytes are compared too.
func Verify(pub ed25519.PublicKey, raw []byte) (Bundle, error) {
	if len(raw) > MaxBundleBytes {
		return Bundle{}, fmt.Errorf("bundle is larger than %d bytes", MaxBundleBytes)
	}
	if err := strictJSON(raw); err != nil {
		return Bundle{}, fmt.Errorf("bundle is ambiguous JSON: %w", err)
	}
	var b Bundle
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		return Bundle{}, err
	}
	if b.Manifest.Format != Format && b.Manifest.Format != FormatV1 {
		return Bundle{}, fmt.Errorf("unknown bundle format %q", b.Manifest.Format)
	}
	m, err := json.Marshal(b.Manifest)
	if err != nil {
		return Bundle{}, err
	}
	sig, err := base64.StdEncoding.DecodeString(b.Signature)
	if err != nil || !ed25519.Verify(pub, m, sig) {
		return Bundle{}, errors.New("manifest signature does not verify")
	}
	for name, want := range b.Manifest.Sections {
		raw, ok := b.Sections[name]
		if !ok {
			return Bundle{}, fmt.Errorf("section %s missing", name)
		}
		canon, err := canonical(raw)
		if err != nil {
			return Bundle{}, fmt.Errorf("section %s: %w", name, err)
		}
		sum, rawSum := sha256.Sum256(canon), sha256.Sum256(raw)
		if hex.EncodeToString(sum[:]) != want && hex.EncodeToString(rawSum[:]) != want {
			return Bundle{}, fmt.Errorf("section %s was altered", name)
		}
	}
	if len(b.Sections) != len(b.Manifest.Sections) {
		return Bundle{}, errors.New("bundle has sections the manifest does not list")
	}
	return b, nil
}

// strictJSON rejects what a lenient reader resolves silently, so the bytes
// mean one thing to every reader: invalid UTF-8, data after the value, and an
// object key that repeats at any depth. Keys compare case-insensitively
// because Go fills a struct field from any case of its name.
func strictJSON(raw []byte) error {
	if !utf8.Valid(raw) {
		return errors.New("invalid UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := strictValue(dec, 1); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("data after the JSON value")
	}
	return nil
}

func strictValue(dec *json.Decoder, depth int) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := tok.(json.Delim); ok && (d == '{' || d == '[') && depth > MaxJSONDepth {
		return fmt.Errorf("nesting deeper than %d levels", MaxJSONDepth)
	}
	switch tok {
	case json.Delim('{'):
		keys := map[string]bool{}
		for dec.More() {
			k, err := dec.Token()
			if err != nil {
				return err
			}
			folded := foldCase(k.(string))
			if keys[folded] {
				return fmt.Errorf("duplicate key %q", k)
			}
			keys[folded] = true
			if err := strictValue(dec, depth+1); err != nil {
				return err
			}
		}
	case json.Delim('['):
		for dec.More() {
			if err := strictValue(dec, depth+1); err != nil {
				return err
			}
		}
	default:
		return nil
	}
	_, err = dec.Token()
	return err
}

// foldCase maps each rune to the smallest rune in its Unicode case-folding
// orbit, so two keys fold equal exactly when strings.EqualFold holds.
func foldCase(s string) string {
	return strings.Map(func(r rune) rune {
		least := r
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			least = min(least, f)
		}
		return least
	}, s)
}
