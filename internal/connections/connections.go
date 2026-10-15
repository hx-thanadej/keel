// Package connections keeps cloud connections (#251, ADR-0022): a cloud key
// a platform admin pastes into Keel, sealed at rest and never shown again,
// that Keel uses as its base identity for that provider. A stored key only
// reads; internal/cloud/tencent refuses every write made with it.
package connections

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/secrets"
	"github.com/hx-thanadej/keel/internal/store"
)

var (
	ErrInvalid  = errors.New("invalid")
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("a Tencent connection already exists; rotate its keys instead")
	// ErrNoSecretsKey means Keel has no KEEL_SECRETS_KEY to seal or open
	// stored keys with.
	ErrNoSecretsKey = errors.New("KEEL_SECRETS_KEY is not set, so Keel cannot store or use cloud keys")
	// ErrUnopenable means a stored key opens with neither KEEL_SECRETS_KEY
	// nor KEEL_SECRETS_KEY_PREVIOUS.
	ErrUnopenable = errors.New("this connection's keys open with neither KEEL_SECRETS_KEY nor KEEL_SECRETS_KEY_PREVIOUS; restore the key, or delete the connection and add it again")
)

// Mode is what Keel may do with a connection. Stored keys only read.
type Mode string

const ReadOnly Mode = "read_only"

// Keys is a cloud key pair. It prints masked, so logging one by mistake
// shows no key material.
type Keys struct {
	SecretID  string `json:"secret_id"`
	SecretKey string `json:"secret_key"`
}

func (k Keys) String() string             { return "Keys{" + mask(k.SecretID) + "}" }
func (k Keys) LogValue() slog.Value       { return slog.StringValue(k.String()) }
func (k Keys) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(k.String())) }

func mask(secretID string) string {
	if len(secretID) < 4 {
		return "****"
	}
	return "****" + secretID[len(secretID)-4:]
}

// Input creates a connection.
type Input struct {
	Provider      string `json:"provider"`
	Name          string `json:"name"`
	PayerUIN      string `json:"payer_uin"`
	DefaultRegion string `json:"default_region"`
	OrgRegion     string `json:"org_region"`
	MemberRole    string `json:"member_role"`
	Mode          Mode   `json:"mode"`
	Keys          `json:"keys"`
}

// Change updates a connection; a nil field keeps its value. Keys, when
// sent, replaces both halves of the key.
type Change struct {
	Name          *string `json:"name"`
	PayerUIN      *string `json:"payer_uin"`
	DefaultRegion *string `json:"default_region"`
	OrgRegion     *string `json:"org_region"`
	MemberRole    *string `json:"member_role"`
	Keys          *Keys   `json:"keys"`
}

// Connection is what the API shows: SecretID is masked to its last four
// characters and the secret key is never returned.
type Connection struct {
	ID            string      `json:"id"`
	Provider      string      `json:"provider"`
	Name          string      `json:"name"`
	PayerUIN      string      `json:"payer_uin"`
	DefaultRegion string      `json:"default_region"`
	OrgRegion     string      `json:"org_region"`
	MemberRole    string      `json:"member_role"`
	Mode          Mode        `json:"mode"`
	SecretID      string      `json:"secret_id"`
	CreatedAt     time.Time   `json:"created_at"`
	CreatedBy     string      `json:"created_by"`
	UpdatedAt     time.Time   `json:"updated_at"`
	RotatedAt     *time.Time  `json:"rotated_at"`
	LastTest      *TestResult `json:"last_test"`
}

// TestResult is the last "Test connection": whom STS said the key is.
type TestResult struct {
	At        time.Time `json:"at"`
	OK        bool      `json:"ok"`
	CallerUIN string    `json:"caller_uin"`
	Detail    string    `json:"detail"`
}

// Service keeps connections in the home Tenant.
type Service struct {
	Store *store.Store
	// Sealer seals keys; nil when KEEL_SECRETS_KEY is unset.
	Sealer *secrets.Sealer
	// Identify asks the provider whose keys these are (Tencent
	// sts:GetCallerIdentity) and returns the account UIN.
	Identify func(ctx context.Context, keys Keys, region string) (string, error)
	Now      func() time.Time
}

func (s Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func (s Service) home(ctx context.Context) (string, error) {
	var h *string
	if err := s.Store.AppPool().QueryRow(ctx, `SELECT home_tenant_id()::text`).Scan(&h); err != nil {
		return "", err
	}
	if h == nil {
		return "", errors.New("no home tenant")
	}
	return *h, nil
}

func (s Service) inHome(ctx context.Context, fn func(tx pgx.Tx, home string) error) error {
	home, err := s.home(ctx)
	if err != nil {
		return err
	}
	return s.Store.InTenant(ctx, home, func(tx pgx.Tx) error { return fn(tx, home) })
}

var (
	uinRE    = regexp.MustCompile(`^[0-9]{5,20}$`)
	regionRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,39}$`)
	roleRE   = regexp.MustCompile(`^[\w+=,.@-]{1,128}$`)
	idRE     = regexp.MustCompile(`^[A-Za-z0-9]{16,128}$`)
	keyRE    = regexp.MustCompile(`^[!-~]{16,128}$`)
)

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrInvalid}, a...)...)
}

func (in *Input) validate() error {
	in.Provider, in.Name = strings.TrimSpace(in.Provider), strings.TrimSpace(in.Name)
	in.PayerUIN, in.DefaultRegion = strings.TrimSpace(in.PayerUIN), strings.TrimSpace(in.DefaultRegion)
	in.OrgRegion, in.MemberRole = strings.TrimSpace(in.OrgRegion), strings.TrimSpace(in.MemberRole)
	switch {
	case in.Provider != "tencent":
		return invalid("provider must be tencent")
	case in.Mode != "" && in.Mode != ReadOnly:
		return invalid("mode must be read_only: Keel never writes with a stored key (ADR-0022)")
	}
	if err := validSettings(in.Name, in.PayerUIN, in.DefaultRegion, in.OrgRegion, in.MemberRole); err != nil {
		return err
	}
	return in.Keys.validate()
}

func validSettings(name, payer, region, orgRegion, memberRole string) error {
	switch {
	case name == "" || len(name) > 100:
		return invalid("name must be 1 to 100 characters")
	case !uinRE.MatchString(payer):
		return invalid("payer_uin must be the payer account's numeric UIN")
	case !regionRE.MatchString(region):
		return invalid("default_region must be a region such as ap-bangkok")
	case orgRegion != "" && !regionRE.MatchString(orgRegion):
		return invalid("org_region must be a region such as ap-bangkok")
	case memberRole != "" && !roleRE.MatchString(memberRole):
		return invalid("member_role must be a CAM role name")
	}
	return nil
}

func (k *Keys) validate() error {
	k.SecretID, k.SecretKey = strings.TrimSpace(k.SecretID), strings.TrimSpace(k.SecretKey)
	if !idRE.MatchString(k.SecretID) {
		return invalid("secret_id must be 16 to 128 letters and digits")
	}
	if !keyRE.MatchString(k.SecretKey) {
		return invalid("secret_key must be 16 to 128 printable characters with no spaces")
	}
	return nil
}

// aad binds a sealed column to its Tenant, row and column.
func aad(tenant, id, column string) []byte {
	return []byte("keel/cloud_connections|" + tenant + "|" + id + "|" + column)
}

func (s Service) seal(tenant, id string, k Keys) (sealedID, sealedKey []byte, err error) {
	if s.Sealer == nil {
		return nil, nil, ErrNoSecretsKey
	}
	if sealedID, err = s.Sealer.Seal([]byte(k.SecretID), aad(tenant, id, "secret_id")); err != nil {
		return nil, nil, err
	}
	sealedKey, err = s.Sealer.Seal([]byte(k.SecretKey), aad(tenant, id, "secret_key"))
	return sealedID, sealedKey, err
}

func (s Service) open(tenant, id string, sealedID, sealedKey []byte) (Keys, error) {
	if s.Sealer == nil {
		return Keys{}, ErrNoSecretsKey
	}
	sid, err := s.Sealer.Open(sealedID, aad(tenant, id, "secret_id"))
	if err != nil {
		return Keys{}, fmt.Errorf("cloud connection %s: %w: %w", id, ErrUnopenable, err)
	}
	skey, err := s.Sealer.Open(sealedKey, aad(tenant, id, "secret_key"))
	if err != nil {
		return Keys{}, fmt.Errorf("cloud connection %s: %w: %w", id, ErrUnopenable, err)
	}
	return Keys{SecretID: string(sid), SecretKey: string(skey)}, nil
}

const cols = `id::text, provider, name, payer_uin, default_region, org_region, member_role, mode, secret_id_last4,
	created_at, created_by, updated_at, rotated_at, last_test_at, coalesce(last_test_ok, false), last_test_uin, last_test_detail`

func scan(r pgx.Row) (Connection, error) {
	var c Connection
	var last4 string
	var testAt *time.Time
	var t TestResult
	err := r.Scan(&c.ID, &c.Provider, &c.Name, &c.PayerUIN, &c.DefaultRegion, &c.OrgRegion, &c.MemberRole, &c.Mode, &last4,
		&c.CreatedAt, &c.CreatedBy, &c.UpdatedAt, &c.RotatedAt, &testAt, &t.OK, &t.CallerUIN, &t.Detail)
	if err != nil {
		return Connection{}, err
	}
	c.SecretID = "****" + last4
	if testAt != nil {
		t.At = testAt.UTC()
		c.LastTest = &t
	}
	return c, nil
}

func record(ctx context.Context, tx pgx.Tx, tenant string, c Connection, typ, op string, kind activity.Kind, by activity.Actor, outcome activity.Outcome, detail string) error {
	_, err := activity.Record(ctx, tx, activity.Activity{TenantID: tenant, Source: "keel/connections", Type: typ, Subject: "cloud_connection/" + c.ID,
		Operation: op, Kind: kind, Actor: by, Outcome: outcome, StatusDetail: detail,
		Resources: []activity.Resource{{Type: "cloud_connection", UID: c.ID}}})
	return err
}

func describe(c Connection) string {
	return fmt.Sprintf("%s connection %q, payer %s, region %s, org region %q, member role %q, mode %s, secret id %s",
		c.Provider, c.Name, c.PayerUIN, c.DefaultRegion, c.OrgRegion, c.MemberRole, c.Mode, c.SecretID)
}

// List returns every connection, masked.
func (s Service) List(ctx context.Context) ([]Connection, error) {
	var out []Connection
	err := s.inHome(ctx, func(tx pgx.Tx, _ string) error {
		rows, err := tx.Query(ctx, `SELECT `+cols+` FROM cloud_connections ORDER BY provider, name`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			c, err := scan(rows)
			if err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}

// Create stores a connection with its key sealed.
func (s Service) Create(ctx context.Context, in Input, by activity.Actor) (Connection, error) {
	if err := in.validate(); err != nil {
		return Connection{}, err
	}
	if s.Sealer == nil {
		return Connection{}, ErrNoSecretsKey
	}
	var out Connection
	err := s.inHome(ctx, func(tx pgx.Tx, home string) error {
		var id string
		if err := tx.QueryRow(ctx, `SELECT uuidv7()::text`).Scan(&id); err != nil {
			return err
		}
		sealedID, sealedKey, err := s.seal(home, id, in.Keys)
		if err != nil {
			return err
		}
		now := s.now()
		out, err = scan(tx.QueryRow(ctx, `INSERT INTO cloud_connections (id, tenant_id, provider, name, payer_uin, default_region, org_region, member_role,
			mode, secret_id_sealed, secret_key_sealed, secret_id_last4, created_at, created_by, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'read_only', $9, $10, $11, $12, $13, $12) RETURNING `+cols,
			id, home, in.Provider, in.Name, in.PayerUIN, in.DefaultRegion, in.OrgRegion, in.MemberRole, sealedID, sealedKey,
			in.SecretID[len(in.SecretID)-4:], now, by.UID))
		if err != nil {
			var pg *pgconn.PgError
			if errors.As(err, &pg) && pg.Code == "23505" {
				return ErrConflict
			}
			return err
		}
		return record(ctx, tx, home, out, "keel.cloud_connection.created", "CreateCloudConnection", activity.Create, by, activity.Success, describe(out))
	})
	return out, err
}

// Update changes a connection's settings and, when Keys is set, rotates its
// key. A rotation clears the last test result, which was for the old key.
func (s Service) Update(ctx context.Context, id string, ch Change, by activity.Actor) (Connection, error) {
	if ch.Keys != nil {
		if err := ch.Keys.validate(); err != nil {
			return Connection{}, err
		}
		if s.Sealer == nil {
			return Connection{}, ErrNoSecretsKey
		}
	}
	var out Connection
	err := s.inHome(ctx, func(tx pgx.Tx, home string) error {
		was, err := scan(tx.QueryRow(ctx, `SELECT `+cols+` FROM cloud_connections WHERE id::text = $1 FOR UPDATE`, id))
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		next := was
		for _, f := range []struct {
			to   *string
			from *string
		}{{&next.Name, ch.Name}, {&next.PayerUIN, ch.PayerUIN}, {&next.DefaultRegion, ch.DefaultRegion}, {&next.OrgRegion, ch.OrgRegion}, {&next.MemberRole, ch.MemberRole}} {
			if f.from != nil {
				*f.to = strings.TrimSpace(*f.from)
			}
		}
		if err := validSettings(next.Name, next.PayerUIN, next.DefaultRegion, next.OrgRegion, next.MemberRole); err != nil {
			return err
		}
		now := s.now()
		out, err = scan(tx.QueryRow(ctx, `UPDATE cloud_connections SET name = $2, payer_uin = $3, default_region = $4, org_region = $5, member_role = $6, updated_at = $7
			WHERE id = $1 RETURNING `+cols, was.ID, next.Name, next.PayerUIN, next.DefaultRegion, next.OrgRegion, next.MemberRole, now))
		if err != nil {
			return err
		}
		if out.Name != was.Name || out.PayerUIN != was.PayerUIN || out.DefaultRegion != was.DefaultRegion || out.OrgRegion != was.OrgRegion || out.MemberRole != was.MemberRole {
			if err := record(ctx, tx, home, out, "keel.cloud_connection.updated", "UpdateCloudConnection", activity.Update, by, activity.Success,
				describe(out)+"; was "+describe(was)); err != nil {
				return err
			}
		}
		if ch.Keys == nil {
			return nil
		}
		sealedID, sealedKey, err := s.seal(home, was.ID, *ch.Keys)
		if err != nil {
			return err
		}
		out, err = scan(tx.QueryRow(ctx, `UPDATE cloud_connections SET secret_id_sealed = $2, secret_key_sealed = $3, secret_id_last4 = $4, rotated_at = $5,
			last_test_at = NULL, last_test_ok = NULL, last_test_uin = '', last_test_detail = '' WHERE id = $1 RETURNING `+cols,
			was.ID, sealedID, sealedKey, ch.Keys.SecretID[len(ch.Keys.SecretID)-4:], now))
		if err != nil {
			return err
		}
		return record(ctx, tx, home, out, "keel.cloud_connection.keys_rotated", "RotateCloudConnectionKeys", activity.Update, by, activity.Success,
			fmt.Sprintf("secret id %s replaced by %s", was.SecretID, out.SecretID))
	})
	return out, err
}

// Delete removes a connection. Keel falls back to its keyless identity.
func (s Service) Delete(ctx context.Context, id string, by activity.Actor) error {
	return s.inHome(ctx, func(tx pgx.Tx, home string) error {
		was, err := scan(tx.QueryRow(ctx, `DELETE FROM cloud_connections WHERE id::text = $1 RETURNING `+cols, id))
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		return record(ctx, tx, home, was, "keel.cloud_connection.deleted", "DeleteCloudConnection", activity.Delete, by, activity.Success, describe(was))
	})
}

// Test asks the provider whom the stored key belongs to and records the
// answer. A key for an account other than the payer fails the test.
func (s Service) Test(ctx context.Context, id string, by activity.Actor) (Connection, error) {
	var (
		c         Connection
		home      string
		keys      Keys
		sealedID  []byte
		sealedKey []byte
	)
	err := s.inHome(ctx, func(tx pgx.Tx, h string) error {
		home = h
		var err error
		c, err = scan(tx.QueryRow(ctx, `SELECT `+cols+` FROM cloud_connections WHERE id::text = $1`, id))
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT secret_id_sealed, secret_key_sealed FROM cloud_connections WHERE id = $1`, c.ID).Scan(&sealedID, &sealedKey)
	})
	if err != nil {
		return Connection{}, err
	}
	if keys, err = s.open(home, c.ID, sealedID, sealedKey); err != nil {
		return Connection{}, err
	}
	res := TestResult{At: s.now()}
	callCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	uin, err := s.Identify(callCtx, keys, c.DefaultRegion)
	cancel()
	switch {
	case err != nil:
		res.Detail = scrub(err.Error(), keys)
	case uin != c.PayerUIN:
		res.CallerUIN, res.Detail = uin, fmt.Sprintf("the key belongs to account %s, not payer %s", uin, c.PayerUIN)
	default:
		res.OK, res.CallerUIN, res.Detail = true, uin, "the key belongs to payer "+uin
	}
	err = s.Store.InTenant(ctx, home, func(tx pgx.Tx) error {
		var err error
		c, err = scan(tx.QueryRow(ctx, `UPDATE cloud_connections SET last_test_at = $2, last_test_ok = $3, last_test_uin = $4, last_test_detail = $5
			WHERE id = $1 RETURNING `+cols, c.ID, res.At, res.OK, res.CallerUIN, res.Detail))
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		outcome := activity.Success
		if !res.OK {
			outcome = activity.Failure
		}
		return record(ctx, tx, home, c, "keel.cloud_connection.tested", "TestCloudConnection", activity.Read, by, outcome, res.Detail)
	})
	return c, err
}

// scrub removes key material a provider error might echo.
func scrub(msg string, k Keys) string {
	for _, s := range []string{k.SecretKey, k.SecretID} {
		if s != "" {
			msg = strings.ReplaceAll(msg, s, "[redacted]")
		}
	}
	return msg
}

// TencentKey returns the stored Tencent key, or ok false when there is no
// Tencent connection. It implements tencent.StoredKey.
func (s Service) TencentKey(ctx context.Context) (secretID, secretKey string, ok bool, err error) {
	var (
		home, id            string
		sealedID, sealedKey []byte
	)
	err = s.inHome(ctx, func(tx pgx.Tx, h string) error {
		home = h
		return tx.QueryRow(ctx, `SELECT id::text, secret_id_sealed, secret_key_sealed FROM cloud_connections WHERE provider = 'tencent'`).Scan(&id, &sealedID, &sealedKey)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", false, nil
	}
	if err != nil {
		return "", "", false, err
	}
	k, err := s.open(home, id, sealedID, sealedKey)
	if err != nil {
		return "", "", false, err
	}
	return k.SecretID, k.SecretKey, true, nil
}

// Tencent returns the Tencent connection's settings, without its key.
func (s Service) Tencent(ctx context.Context) (Connection, bool, error) {
	cs, err := s.List(ctx)
	if err != nil {
		return Connection{}, false, err
	}
	for _, c := range cs {
		if c.Provider == "tencent" {
			return c, true, nil
		}
	}
	return Connection{}, false, nil
}

// Prepare runs at start. Stored connections need KEEL_SECRETS_KEY. One
// sealed with KEEL_SECRETS_KEY_PREVIOUS is resealed with the current key,
// so the previous key can be dropped once Keel has started. One that opens
// with neither is reported and left unusable rather than blocking start, so
// an admin can replace it after losing the key.
func (s Service) Prepare(ctx context.Context) error {
	var home *string
	if err := s.Store.AppPool().QueryRow(ctx, `SELECT home_tenant_id()::text`).Scan(&home); err != nil || home == nil {
		return err // no home Tenant yet: no connections
	}
	return s.Store.InTenant(ctx, *home, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id::text, secret_id_sealed, secret_key_sealed FROM cloud_connections FOR UPDATE`)
		if err != nil {
			return err
		}
		type row struct {
			id        string
			sealedID  []byte
			sealedKey []byte
		}
		all, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (row, error) {
			var x row
			return x, r.Scan(&x.id, &x.sealedID, &x.sealedKey)
		})
		if err != nil {
			return err
		}
		if len(all) > 0 && s.Sealer == nil {
			return fmt.Errorf("%d cloud connection(s) stored: %w", len(all), ErrNoSecretsKey)
		}
		for _, r := range all {
			k, err := s.open(*home, r.id, r.sealedID, r.sealedKey)
			if err != nil {
				// It stays unusable, so Keel fails closed when it needs it,
				// and a platform admin can delete it and add it again.
				slog.Error("ALERT cloud connection cannot be opened; delete it and add it again, or restore its key", "err", err)
				continue
			}
			if !s.Sealer.Stale(r.sealedID) && !s.Sealer.Stale(r.sealedKey) {
				continue
			}
			sealedID, sealedKey, err := s.seal(*home, r.id, k)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE cloud_connections SET secret_id_sealed = $2, secret_key_sealed = $3 WHERE id = $1`, r.id, sealedID, sealedKey); err != nil {
				return err
			}
			if _, err := activity.Record(ctx, tx, activity.Activity{TenantID: *home, Source: "keel/connections", Type: "keel.cloud_connection.resealed",
				Subject: "cloud_connection/" + r.id, Operation: "ResealCloudConnection", Kind: activity.Update,
				Actor: activity.Actor{Type: activity.ActorKeel, UID: "keel:connections"}, Outcome: activity.Success,
				StatusDetail: "resealed under the current KEEL_SECRETS_KEY"}); err != nil {
				return err
			}
		}
		return nil
	})
}
