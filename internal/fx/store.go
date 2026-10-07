package fx

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/store"
)

// DB stores rates in Postgres.
type DB struct{ Store *store.Store }

// SaveRates inserts rates not already stored and returns how many were new.
func (d DB) SaveRates(ctx context.Context, rates []Rate) (int, error) {
	var home *string
	if err := d.Store.AppPool().QueryRow(ctx, `SELECT home_tenant_id()::text`).Scan(&home); err != nil || home == nil {
		return 0, errors.New("fx: no home tenant")
	}
	n := 0
	err := d.Store.InTenant(ctx, *home, func(tx pgx.Tx) error {
		for _, r := range rates {
			tag, err := tx.Exec(ctx, `INSERT INTO fx_rates (tenant_id, day, currency, per_eur) VALUES ($1, $2, $3, $4::numeric) ON CONFLICT DO NOTHING`, *home, r.Day, r.Currency, r.PerEUR)
			if err != nil {
				return err
			}
			n += int(tag.RowsAffected())
		}
		return nil
	})
	return n, err
}

// Earliest returns the oldest stored rate day, or zero time when none.
func (d DB) Earliest(ctx context.Context) (time.Time, error) {
	var t *time.Time
	err := d.Store.AppPool().QueryRow(ctx, `SELECT min(day)::timestamptz FROM fx_rates_days()`).Scan(&t)
	if err != nil || t == nil {
		return time.Time{}, err
	}
	return *t, nil
}
