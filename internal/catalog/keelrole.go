package catalog

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/store"
)

// KeelAccount is a provider account Keel's own roles may enter: one no
// Tenant holds as client-owned (ADR-0018). Only ReachKeelAccount builds one,
// and Enter checks again for every assumption, so a KeelAccount kept across
// an ownership switch is refused. The zero KeelAccount is refused.
type KeelAccount struct {
	st                   *store.Store
	provider, externalID string
}

// ReachKeelAccount is externalID on provider if Keel's own roles may enter
// it. The error wraps ErrClientOwned when a Tenant holds it as client-owned.
func ReachKeelAccount(ctx context.Context, st *store.Store, provider, externalID string) (KeelAccount, error) {
	a := KeelAccount{st: st, provider: provider, externalID: externalID}
	if err := a.Enter(ctx, func() error { return nil }); err != nil {
		return KeelAccount{}, err
	}
	return a, nil
}

// ID is the account's id at its provider.
func (a KeelAccount) ID() string { return a.externalID }

// Enter runs assume, which assumes Keel's role in the account, only while
// no Tenant holds the account as client-owned. It holds the account's
// ownership lock shared until assume returns, and every write that can make
// the account client-owned takes that lock exclusively (migration 00055):
// such a write waits for assume, and one already in flight commits before
// the check reads. The error wraps ErrClientOwned when the account is
// client-owned, archived or not.
func (a KeelAccount) Enter(ctx context.Context, assume func() error) error {
	if a.st == nil {
		return errors.New("keel's own role: the account was not checked with ReachKeelAccount")
	}
	return pgx.BeginFunc(ctx, a.st.AppPool(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock_shared(account_lock_key($1, $2))`, a.provider, a.externalID); err != nil {
			return fmt.Errorf("ownership lock of %s account %s: %w", a.provider, a.externalID, err)
		}
		var ownership *string
		if err := tx.QueryRow(ctx, `SELECT account_ownership($1, $2)`, a.provider, a.externalID).Scan(&ownership); err != nil {
			return fmt.Errorf("ownership of %s account %s: %w", a.provider, a.externalID, err)
		}
		if ownership != nil && Ownership(*ownership) == OwnershipClient {
			return fmt.Errorf("keel's own role in %s account %s: %w", a.provider, a.externalID, ErrClientOwned)
		}
		return assume()
	})
}

// ClientReadRole is the read-only role a client granted Keel in its payer,
// with Keel's ExternalId for that payer, as the payer's registration in its
// Tenant holds them (ADR-0018). Only LoadClientReadRole builds one; the zero
// ClientReadRole has no ExternalId and is refused when assumed.
type ClientReadRole struct {
	payer, arn, externalID string
}

// LoadClientReadRole is payer's read-only role on provider, registered as a
// client payer of a live client-owned Cloud Account in tenant.
func LoadClientReadRole(ctx context.Context, st *store.Store, provider, tenant, payer string) (ClientReadRole, error) {
	r := ClientReadRole{payer: payer}
	err := st.AppPool().QueryRow(ctx, `SELECT role_arn, role_external_id FROM client_payers_for($1) WHERE tenant_id::text = $2 AND external_id = $3`,
		provider, tenant, payer).Scan(&r.arn, &r.externalID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ClientReadRole{}, fmt.Errorf("%s payer %s is not a client payer of tenant %s", provider, payer, tenant)
	}
	if err != nil {
		return ClientReadRole{}, fmt.Errorf("read-only role of %s payer %s: %w", provider, payer, err)
	}
	return r, nil
}

// Payer is the client payer account the role lives in.
func (r ClientReadRole) Payer() string { return r.payer }

// ARN is the role's ARN, as the client registered it.
func (r ClientReadRole) ARN() string { return r.arn }

// ExternalID is Keel's ExternalId for the payer, which the role's trust
// policy requires.
func (r ClientReadRole) ExternalID() string { return r.externalID }
