package budget

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/catalog"
)

// NativeSpec is what a provider budget should contain to mirror a Keel Budget.
type NativeSpec struct {
	Name       string      `json:"name"`
	Year       int         `json:"year"`
	Accounts   []string    `json:"accounts"` // provider account ids in scope, sorted
	Monthly    [12]string  `json:"monthly"`  // in the provider's billing currency, 2 decimals
	Currency   string      `json:"currency"`
	Basis      string      `json:"basis"` // effective | billed
	Thresholds []Threshold `json:"thresholds"`
}

// Native is a provider's budget API.
type Native interface {
	Provider() string
	Create(ctx context.Context, s NativeSpec) (id string, err error)
	Update(ctx context.Context, id string, s NativeSpec) error
	Get(ctx context.Context, id string) (NativeSpec, bool, error)
	Delete(ctx context.Context, id string) error
}

// ThresholdMirroring is implemented by Natives that can only mirror
// thresholds in some configurations (AWS needs a notification subscriber).
// When it reports false, thresholds are left out of the spec on both sides.
type ThresholdMirroring interface {
	MirrorsThresholds() bool
}

// Mirror keeps native provider budgets in step with Keel Budgets that opt in
// (#39, ADR-0012). Keel stays the source of truth: edits made in a provider
// console are drift, corrected and reported.
type Mirror struct {
	Service         Service
	Natives         map[string]Native // by provider
	BillingCurrency map[string]string // provider → currency its budgets use
	Now             func() time.Time
}

// MirrorReport counts what a sync did.
type MirrorReport struct {
	Created, Updated, Recreated, Deleted int
	Drift                                []string
}

// fxTolerance: monthly amounts moving less than this (exchange-rate noise) are not drift.
const fxTolerance = 0.01

// SyncAll reconciles every Tenant's mirrors.
func (m Mirror) SyncAll(ctx context.Context) (MirrorReport, error) {
	var rep MirrorReport
	rows, err := m.Service.Store.AppPool().Query(ctx, `SELECT t::text FROM tenant_ids() AS t`)
	if err != nil {
		return rep, err
	}
	tenants, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return rep, err
	}
	var errs []error
	for _, t := range tenants {
		if err := m.tenant(ctx, t, &rep); err != nil {
			errs = append(errs, fmt.Errorf("tenant %s: %w", t, err))
		}
	}
	return rep, errors.Join(errs...)
}

type mirrorRow struct {
	budgetID, provider, nativeID string
	spec                         NativeSpec
}

func (m Mirror) tenant(ctx context.Context, tenant string, rep *MirrorReport) error {
	now := time.Now
	if m.Now != nil {
		now = m.Now
	}
	var budgets []Budget
	var existing []mirrorRow
	err := m.Service.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+cols+` FROM budgets WHERE archived_at IS NULL AND mirror_native`)
		if err != nil {
			return err
		}
		if budgets, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (Budget, error) { return scan(r) }); err != nil {
			return err
		}
		rows, err = tx.Query(ctx, `SELECT budget_id::text, provider, native_id, spec FROM budget_mirrors WHERE deleted_at IS NULL`)
		if err != nil {
			return err
		}
		existing, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (mirrorRow, error) {
			var x mirrorRow
			var spec []byte
			err := r.Scan(&x.budgetID, &x.provider, &x.nativeID, &spec)
			if err == nil {
				err = json.Unmarshal(spec, &x.spec)
			}
			return x, err
		})
		return err
	})
	if err != nil {
		return err
	}

	want := map[string]NativeSpec{} // budget|provider
	byKey := map[string]Budget{}
	for _, b := range budgets {
		for provider, native := range m.Natives {
			if b.Provider != nil && *b.Provider != provider {
				continue
			}
			spec, ok, err := m.spec(ctx, tenant, b, native.Provider(), now())
			if err != nil {
				return err
			}
			if ok {
				want[b.ID+"|"+provider] = spec
				byKey[b.ID+"|"+provider] = b
			}
		}
	}

	// Remove mirrors no longer wanted (budget archived, mirroring off, scope empty).
	for _, x := range existing {
		if _, keep := want[x.budgetID+"|"+x.provider]; keep {
			continue
		}
		native, ok := m.Natives[x.provider]
		if !ok {
			continue
		}
		if err := native.Delete(ctx, x.nativeID); err != nil {
			return fmt.Errorf("delete %s budget %s: %w", x.provider, x.nativeID, err)
		}
		rep.Deleted++
		if err := m.save(ctx, tenant, x.budgetID, x.provider, `UPDATE budget_mirrors SET deleted_at = now() WHERE budget_id = $1 AND provider = $2`,
			"keel.budget.mirror_deleted", "", x.budgetID, x.provider); err != nil {
			return err
		}
	}

	for key, spec := range want {
		b := byKey[key]
		provider := key[strings.Index(key, "|")+1:]
		native := m.Natives[provider]
		var cur *mirrorRow
		for i := range existing {
			if existing[i].budgetID == b.ID && existing[i].provider == provider {
				cur = &existing[i]
			}
		}
		specJSON, _ := json.Marshal(spec)
		if cur == nil {
			id, err := native.Create(ctx, spec)
			if err != nil {
				return fmt.Errorf("create %s budget: %w", provider, err)
			}
			rep.Created++
			if err := m.save(ctx, tenant, b.ID, provider, `INSERT INTO budget_mirrors (tenant_id, budget_id, provider, native_id, spec) VALUES (current_tenant_id(), $1, $2, $3, $4)
				ON CONFLICT (budget_id, provider) DO UPDATE SET native_id = excluded.native_id, spec = excluded.spec, synced_at = now(), deleted_at = NULL, last_drift = NULL`,
				"keel.budget.mirror_created", provider+" budget "+id, b.ID, provider, id, specJSON); err != nil {
				return err
			}
			continue
		}
		got, found, err := native.Get(ctx, cur.nativeID)
		if err != nil {
			return fmt.Errorf("get %s budget %s: %w", provider, cur.nativeID, err)
		}
		if !found {
			id, err := native.Create(ctx, spec)
			if err != nil {
				return fmt.Errorf("recreate %s budget: %w", provider, err)
			}
			rep.Recreated++
			drift := fmt.Sprintf("%s budget %s was deleted outside Keel; recreated as %s", provider, cur.nativeID, id)
			rep.Drift = append(rep.Drift, drift)
			if err := m.save(ctx, tenant, b.ID, provider, `UPDATE budget_mirrors SET native_id = $3, spec = $4, synced_at = now(), last_drift = $5 WHERE budget_id = $1 AND provider = $2`,
				"keel.budget.mirror_recreated", drift, b.ID, provider, id, specJSON, drift); err != nil {
				return err
			}
			continue
		}
		reasons := differences(got, spec)
		if len(reasons) == 0 {
			continue
		}
		if err := native.Update(ctx, cur.nativeID, spec); err != nil {
			return fmt.Errorf("update %s budget %s: %w", provider, cur.nativeID, err)
		}
		rep.Updated++
		drift := fmt.Sprintf("%s budget %s differed (%s); corrected", provider, cur.nativeID, strings.Join(reasons, ", "))
		rep.Drift = append(rep.Drift, drift)
		if err := m.save(ctx, tenant, b.ID, provider, `UPDATE budget_mirrors SET spec = $3, synced_at = now(), last_drift = $4 WHERE budget_id = $1 AND provider = $2`,
			"keel.budget.mirror_drift_corrected", drift, b.ID, provider, specJSON, drift); err != nil {
			return err
		}
	}
	return nil
}

// spec computes the native budget for b on one provider; false when the
// scope has no accounts on that provider or amounts can't be converted yet.
func (m Mirror) spec(ctx context.Context, tenant string, b Budget, provider string, now time.Time) (NativeSpec, bool, error) {
	cur := m.BillingCurrency[provider]
	if cur == "" {
		cur = "USD"
	}
	s := NativeSpec{Name: b.Name, Year: b.Year, Currency: cur, Basis: b.CostBasis, Thresholds: b.Thresholds}
	if tm, ok := m.Natives[provider].(ThresholdMirroring); ok && !tm.MirrorsThresholds() {
		s.Thresholds = nil
	}
	ok := true
	err := m.Service.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT a.id::text, a.external_id FROM cloud_accounts a JOIN environments e ON e.id = a.environment_id
			WHERE a.provider = $1 AND a.archived_at IS NULL AND e.project_id = $2 AND ($3::uuid IS NULL OR e.id = $3) ORDER BY 2`, provider, b.ProjectID, b.EnvironmentID)
		if err != nil {
			return err
		}
		scoped, err := pgx.CollectRows(rows, pgx.RowToStructByPos[struct{ ID, External string }])
		if err != nil {
			return err
		}
		// A client-owned account is billed to the client's payer, not ours,
		// and Keel creates nothing in the client's organisation (ADR-0018).
		for _, a := range scoped {
			client, err := catalog.IsClientOwned(ctx, tx, a.ID)
			if err != nil {
				return err
			}
			if !client {
				s.Accounts = append(s.Accounts, a.External)
			}
		}
		if len(s.Accounts) == 0 {
			ok = false
			return nil
		}
		day := now.UTC().Format("2006-01-02")
		for mth := time.January; mth <= time.December; mth++ {
			var v *string
			if err := tx.QueryRow(ctx, `SELECT round(fx_convert($1::numeric, $2, $3, $4::date), 2)::text`, b.monthRat(mth).FloatString(6), b.Currency, cur, day).Scan(&v); err != nil {
				return err
			}
			if v == nil {
				ok = false
				return nil
			}
			s.Monthly[mth-1] = *v
		}
		return nil
	})
	return s, ok, err
}

func (m Mirror) save(ctx context.Context, tenant, budgetID, provider, sql, actType, detail string, args ...any) error {
	return m.Service.Store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, sql, args...); err != nil {
			return err
		}
		_, err := activity.Record(ctx, tx, activity.Activity{TenantID: tenant, Source: "keel/budget", Type: actType, Subject: "budget/" + budgetID,
			Operation: "MirrorBudget", Kind: activity.Update, Actor: keelActor, Resources: []activity.Resource{{Type: "budget", UID: budgetID}},
			Outcome: activity.Success, StatusDetail: strings.TrimSpace(provider + " " + detail)})
		return err
	})
}

// differences lists how a provider budget departs from what Keel wants.
func differences(got, want NativeSpec) []string {
	var out []string
	if !sameMonthly(got, want) {
		out = append(out, "monthly amounts")
	}
	if !slices.Equal(got.Accounts, want.Accounts) {
		out = append(out, "accounts")
	}
	if got.Basis != want.Basis || got.Currency != want.Currency {
		out = append(out, "cost basis")
	}
	if !slices.Equal(got.Thresholds, want.Thresholds) {
		out = append(out, "thresholds")
	}
	return out
}

func sameMonthly(a, b NativeSpec) bool {
	for i := range a.Monthly {
		x, okx := new(big.Rat).SetString(a.Monthly[i])
		y, oky := new(big.Rat).SetString(b.Monthly[i])
		if !okx || !oky {
			return false
		}
		if y.Sign() == 0 {
			if x.Sign() != 0 {
				return false
			}
			continue
		}
		rel, _ := new(big.Rat).Abs(new(big.Rat).Quo(new(big.Rat).Sub(x, y), y)).Float64()
		if rel > fxTolerance {
			return false
		}
	}
	return true
}

// MirrorStatus is a native mirror as seen from Keel.
type MirrorStatus struct {
	Provider  string     `json:"provider"`
	NativeID  string     `json:"native_id"`
	SyncedAt  time.Time  `json:"synced_at"`
	LastDrift *string    `json:"last_drift"`
	DeletedAt *time.Time `json:"deleted_at"`
}

// Mirrors lists a Budget's native mirrors.
func (s Service) Mirrors(ctx context.Context, tenantID, budgetID string) ([]MirrorStatus, error) {
	var out []MirrorStatus
	err := s.Store.InTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT provider, native_id, synced_at, last_drift, deleted_at FROM budget_mirrors WHERE budget_id = $1 ORDER BY provider`, budgetID)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, pgx.RowToStructByPos[MirrorStatus])
		return err
	})
	return out, mapErr(err)
}
