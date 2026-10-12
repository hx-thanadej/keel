// Package leaks handles cloud keys found in code (#136, ADR-0007): a signed
// GitHub secret-scanning webhook names the alert; Keel reads the key id,
// finds which account and user own it, disables it at once, and raises a
// critical Finding saying what it did. The secret itself is never stored or
// logged. Rotation means no replacement key: the owner moves to workload
// identity.
package leaks

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/catalog"
	"github.com/hx-thanadej/keel/internal/store"
)

// Key is a leaked access key's public half and its owner.
type Key struct {
	Provider string
	KeyID    string
	Account  string
	OwnerUin string
	Owner    string
}

// Keys finds and disables access keys in the accounts Keel manages.
type Keys interface {
	Provider() string
	// Find looks the key id up in every given account.
	Find(ctx context.Context, keyID string, accounts []string) (Key, bool, error)
	Disable(ctx context.Context, k Key) error
}

// Alerts reads a secret-scanning alert's secret (to get the key id).
type Alerts interface {
	Secret(ctx context.Context, repo string, number int) (secretType, secret string, err error)
}

// Service processes alerts.
type Service struct {
	Store         *store.Store
	WebhookSecret []byte
	Alerts        Alerts
	Keys          map[string]Keys  // by provider
	Now           func() time.Time // defaults to time.Now
	river         *river.Client[pgx.Tx]
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

var (
	ErrSignature = errors.New("bad webhook signature")
	ErrReplay    = errors.New("delivery already processed")
)

// Verify checks GitHub's X-Hub-Signature-256 header.
func (s *Service) Verify(body []byte, header string) error {
	if len(s.WebhookSecret) == 0 {
		return fmt.Errorf("%w: no webhook secret configured", ErrSignature)
	}
	mac := hmac.New(sha256.New, s.WebhookSecret)
	mac.Write(body)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(want), []byte(header)) {
		return ErrSignature
	}
	return nil
}

// Register adds the processing worker.
func (s *Service) Register(w *river.Workers) { river.AddWorker(w, &worker{s: s}) }

// SetClient gives the Service its River client.
func (s *Service) SetClient(c *river.Client[pgx.Tx]) { s.river = c }

type jobArgs struct {
	Repo     string `json:"repo"`
	RepoID   int64  `json:"repo_id,omitempty"`
	Number   int    `json:"number"`
	Delivery string `json:"delivery"`
}

func (jobArgs) Kind() string { return "keel_leaked_key" }

func (s *Service) home(ctx context.Context) (string, error) {
	var h *string
	if err := s.Store.AppPool().QueryRow(ctx, `SELECT home_tenant_id()::text`).Scan(&h); err != nil {
		return "", err
	}
	if h == nil {
		return "", errors.New("no home tenant")
	}
	return *h, nil
}

// Receive records a delivery once and queues alerts for processing. The
// caller has already verified the signature.
func (s *Service) Receive(ctx context.Context, delivery, event string, body []byte) error {
	home, err := s.home(ctx)
	if err != nil {
		return err
	}
	return s.Store.InTenant(ctx, home, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `INSERT INTO webhook_deliveries (tenant_id, source, delivery_id, event) VALUES ($1, 'github', $2, $3) ON CONFLICT DO NOTHING`, home, delivery, event)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrReplay
		}
		if event != "secret_scanning_alert" {
			return nil
		}
		var p struct {
			Action string `json:"action"`
			Alert  struct {
				Number int `json:"number"`
			} `json:"alert"`
			Repository struct {
				ID       int64  `json:"id"`
				FullName string `json:"full_name"`
			} `json:"repository"`
		}
		if err := json.Unmarshal(body, &p); err != nil {
			return err
		}
		if p.Action != "created" && p.Action != "reopened" && p.Action != "publicly_leaked" {
			return nil
		}
		if s.river == nil {
			return errors.New("leaked-key processing has no River client")
		}
		_, err = s.river.InsertTx(ctx, tx, jobArgs{Repo: p.Repository.FullName, RepoID: p.Repository.ID, Number: p.Alert.Number, Delivery: delivery}, &river.InsertOpts{MaxAttempts: 10})
		return err
	})
}

var keyPatterns = map[string]*regexp.Regexp{
	"tencent": regexp.MustCompile(`AKID[0-9A-Za-z]{32}`),
	"aws":     regexp.MustCompile(`(AKIA|ASIA)[0-9A-Z]{16}`),
}

// providerOf maps GitHub secret types to providers.
func providerOf(secretType string) string {
	switch {
	case strings.HasPrefix(secretType, "tencent"):
		return "tencent"
	case strings.HasPrefix(secretType, "aws"):
		return "aws"
	}
	return ""
}

// mask keeps the first 8 characters of a key id.
func mask(id string) string {
	if len(id) <= 8 {
		return id
	}
	return id[:8] + strings.Repeat("*", len(id)-8)
}

var keelActor = activity.Actor{Type: activity.ActorKeel, UID: "keel:leaked-keys"}

// Repo is the repository an alert names: GitHub's id, which Services
// record, and its owner/name.
type Repo struct {
	ID   int64
	Name string
}

// Process handles one alert: find, disable, report.
func (s *Service) Process(ctx context.Context, r Repo, number int) error {
	repo := r.Name
	typ, secret, err := s.Alerts.Secret(ctx, repo, number)
	if err != nil {
		return err
	}
	provider := providerOf(typ)
	if provider == "" {
		return nil // not a cloud key; GitHub's own alert workflow handles it
	}
	keyID := keyPatterns[provider].FindString(secret) // only the public key id is kept; the secret goes out of scope here
	home, err := s.home(ctx)
	if err != nil {
		return err
	}
	// Every account Keel manages for this provider, with the Tenant that owns it.
	type acct struct{ tenant, id, external, env, project string }
	var accounts []acct
	rows, err := s.Store.AppPool().Query(ctx, `SELECT t::text FROM tenant_ids() AS t`)
	if err != nil {
		return err
	}
	tenants, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	for _, t := range tenants {
		if err := s.Store.InTenant(ctx, t, func(tx pgx.Tx) error {
			rows, err := tx.Query(ctx, `SELECT a.id::text, a.external_id, coalesce(a.environment_id::text, ''), coalesce(e.project_id::text, '') FROM cloud_accounts a
				LEFT JOIN environments e ON e.id = a.environment_id WHERE a.provider = $1 AND a.archived_at IS NULL`, provider)
			if err != nil {
				return err
			}
			for rows.Next() {
				a := acct{tenant: t}
				if err := rows.Scan(&a.id, &a.external, &a.env, &a.project); err != nil {
					return err
				}
				accounts = append(accounts, a)
			}
			return rows.Err()
		}); err != nil {
			return err
		}
	}
	ids := make([]string, 0, len(accounts))
	for _, a := range accounts {
		ids = append(ids, a.external)
	}
	clients, err := catalog.ClientOwned(ctx, s.Store, provider, ids)
	if err != nil {
		return err
	}
	ids = slices.DeleteFunc(ids, func(id string) bool { return clients[id] }) // searched only through Keel's own role
	var found Key
	ok, searched := false, false
	if k := s.Keys[provider]; k != nil && keyID != "" {
		if found, ok, err = k.Find(ctx, keyID, ids); err != nil {
			return err
		}
		searched = true
	}
	title := fmt.Sprintf("Leaked %s access key %s in %s", provider, mask(keyID), repo)
	detail := func() map[string]any {
		return map[string]any{"repository": repo, "alert": number, "key": mask(keyID), "provider": provider}
	}
	report := func(t target, title string, detail map[string]any, act string, disabled bool) error {
		return s.report(ctx, t, provider, keyID, repo, number, title, detail, act, disabled)
	}
	if ok {
		owner := target{tenant: home}
		for _, a := range accounts {
			if a.external == found.Account {
				owner = target{tenant: a.tenant, id: a.id, project: a.project, env: a.env}
			}
		}
		d := detail()
		d["account"], d["owner"] = found.Account, found.Owner
		err := catalog.RequirePlatformOwned(ctx, s.Store, owner.tenant, owner.id, "DisableLeakedKey", keelActor)
		if errors.Is(err, catalog.ErrClientOwned) { // switched to client-owned since the search
			d["client_owned"] = true
			return report(owner, fmt.Sprintf("Leaked %s access key %s of %s in client-owned %s is still active", provider, mask(keyID), found.Owner, found.Account), d,
				"Keel is read-only in the client's organisation (ADR-0018) and did not disable it: the client must disable it now and move the owner to workload identity", false)
		}
		if err != nil {
			return err
		}
		if err := s.Keys[provider].Disable(ctx, found); err != nil {
			return err // retried: the key must not stay active
		}
		return report(owner, fmt.Sprintf("Leaked %s access key %s of %s in %s was disabled", provider, mask(keyID), found.Owner, found.Account), d,
			"disabled at once; move the owner to workload identity (no replacement key)", true)
	}
	// Not in a platform-owned account. Keel does not search client-owned
	// accounts (ADR-0018), so when a client's Service owns the repository the
	// key is most likely the client's: only they can find and disable it.
	unsearched := map[string][]string{} // tenant → its client-owned accounts
	var all []string
	for _, a := range accounts {
		if clients[a.external] {
			unsearched[a.tenant] = append(unsearched[a.tenant], a.external)
			all = append(all, a.external)
		}
	}
	if searched && r.ID != 0 {
		rows, err := s.Store.AppPool().Query(ctx, `SELECT tenant_id::text, service_id::text FROM services_by_repository($1)`, r.ID)
		if err != nil {
			return err
		}
		services, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (target, error) {
			var t target
			return t, row.Scan(&t.tenant, &t.service)
		})
		if err != nil {
			return err
		}
		reported := map[string]bool{}
		for _, t := range services {
			if len(unsearched[t.tenant]) == 0 || reported[t.tenant] {
				continue
			}
			reported[t.tenant] = true
			d := detail()
			d["client_owned_accounts"] = unsearched[t.tenant]
			act := fmt.Sprintf("the repository belongs to your Service and the key is not in the platform-owned accounts Keel searched. Keel does not search client-owned accounts (ADR-0018): you must find this key in your accounts (%s), disable it now and move the owner to workload identity",
				strings.Join(unsearched[t.tenant], ", "))
			if err := report(t, title, d, act, false); err != nil {
				return err
			}
		}
		if len(reported) > 0 {
			return nil
		}
	}
	d := detail()
	act := "Keel could not search for this key: find and disable it by hand"
	if searched {
		act = "the key is not in the platform-owned accounts Keel searched"
		if len(all) > 0 {
			d["client_owned_accounts"] = all
			act += fmt.Sprintf(", and Keel does not search client-owned accounts (ADR-0018): %s", strings.Join(all, ", "))
		}
		act += ". Find and disable it by hand"
	}
	return report(target{tenant: home}, title, d, act, false)
}

// target is where a leaked key's Finding is raised: a Tenant, and the
// account or Service the key is attributed to there.
type target struct{ tenant, id, project, env, service string }

func (s *Service) report(ctx context.Context, t target, provider, keyID, repo string, number int, title string, detail map[string]any, act string, disabled bool) error {
	detail["action"] = act
	raw, _ := json.Marshal(detail)
	return s.Store.InTenant(ctx, t.tenant, func(tx pgx.Tx) error {
		var project, env, service, team *string
		if t.project != "" {
			project, env = &t.project, &t.env
		}
		if t.service != "" {
			var p, tm string
			if err := tx.QueryRow(ctx, `SELECT project_id::text, team_id::text FROM services WHERE id = $1`, t.service).Scan(&p, &tm); err != nil {
				return err
			}
			project, service, team = &p, &t.service, &tm
		}
		if _, err := tx.Exec(ctx, `INSERT INTO findings (tenant_id, kind, fingerprint, severity, title, detail, project_id, environment_id, service_id, owner_team_id, first_seen_at)
			VALUES ($1, 'leaked_key', $2, 'critical', $3, $4, $5, $6, $7, coalesce($8::uuid, (SELECT team_id FROM projects WHERE id = $5)), $9)
			ON CONFLICT (tenant_id, fingerprint) WHERE status = 'open' DO UPDATE SET last_seen_at = now(), detail = excluded.detail`,
			t.tenant, "leaked_key:"+provider+":"+mask(keyID), title, raw, project, env, service, team, s.now()); err != nil {
			return err
		}
		outcome := activity.Success
		if !disabled {
			outcome = activity.Failure
		}
		_, err := activity.Record(ctx, tx, activity.Activity{TenantID: t.tenant, Source: "keel/leaked-keys", Type: "keel.leaked_key.handled", Subject: "repository/" + repo,
			Operation: "DisableLeakedKey", Kind: activity.Update, Actor: keelActor, Outcome: outcome, StatusDetail: title + ": " + act,
			Why: activity.Why{Reason: fmt.Sprintf("GitHub secret scanning alert %s#%d", repo, number)}})
		return err
	})
}

type worker struct {
	river.WorkerDefaults[jobArgs]
	s *Service
}

func (w *worker) Work(ctx context.Context, job *river.Job[jobArgs]) error {
	return w.s.Process(ctx, Repo{ID: job.Args.RepoID, Name: job.Args.Repo}, job.Args.Number)
}
