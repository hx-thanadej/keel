package catalog

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/store"
)

// KeelAccount is a provider account Keel's own roles may enter: one no
// Tenant holds as client-owned (ADR-0018). Only ReachKeelAccount builds one,
// and Enter and Check check again on every use, so a KeelAccount kept across
// an ownership switch is refused. The zero KeelAccount is refused.
type KeelAccount struct {
	st                   *store.Store
	provider, externalID string
}

// ReachKeelAccount is externalID on provider if Keel's own roles may enter
// it. The error wraps ErrClientOwned when a Tenant holds it as client-owned.
func ReachKeelAccount(ctx context.Context, st *store.Store, provider, externalID string) (KeelAccount, error) {
	a := KeelAccount{st: st, provider: provider, externalID: externalID}
	if err := a.Check(ctx); err != nil {
		return KeelAccount{}, err
	}
	return a, nil
}

// ID is the account's id at its provider.
func (a KeelAccount) ID() string { return a.externalID }

// leaseFor bounds how long an ownership switch waits for one assumption.
// It outlasts the STS client's 60-second request timeout.
const leaseFor = 2 * time.Minute

// Enter runs assume, which assumes Keel's role in the account, only while
// no Tenant holds the account as client-owned. It checks ownership under
// the account's ownership lock and leases the account, holding no
// connection while assume runs; every write that can make the account
// client-owned takes that lock and waits out the leases (migrations 00055,
// 00056). Such a write in flight is waited for and then seen; one that
// starts during assume waits for it. If assume outlives the lease, it is
// refused unless the account is still Keel's. The error wraps
// ErrClientOwned when the account is client-owned, archived or not.
func (a KeelAccount) Enter(ctx context.Context, assume func() error) (err error) {
	lease, err := a.enter(ctx, leaseFor)
	if err != nil {
		return err
	}
	defer func() {
		var live *bool
		if lerr := a.st.AppPool().QueryRow(context.WithoutCancel(ctx), `SELECT leave_keel_account($1)`, lease).Scan(&live); lerr != nil {
			err = errors.Join(err, fmt.Errorf("leave %s account %s: %w", a.provider, a.externalID, lerr))
		} else if err == nil && (live == nil || !*live) {
			err = a.Check(ctx)
		}
	}()
	return assume()
}

// Check is nil while no Tenant holds the account as client-owned; an
// ownership switch in flight is waited for and then seen. Keel's cached
// sessions in the account are checked with it on every use. The error
// wraps ErrClientOwned when the account is client-owned, archived or not.
func (a KeelAccount) Check(ctx context.Context) error {
	_, err := a.enter(ctx, 0)
	return err
}

func (a KeelAccount) enter(ctx context.Context, lease time.Duration) (int64, error) {
	if a.st == nil {
		return 0, errors.New("keel's own role: the account was not checked with ReachKeelAccount")
	}
	var id *int64
	if err := a.st.AppPool().QueryRow(ctx, `SELECT enter_keel_account($1, $2, $3)`, a.provider, a.externalID, lease).Scan(&id); err != nil {
		return 0, fmt.Errorf("ownership of %s account %s: %w", a.provider, a.externalID, err)
	}
	if id == nil {
		return 0, fmt.Errorf("keel's own role in %s account %s: %w", a.provider, a.externalID, ErrClientOwned)
	}
	return *id, nil
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
