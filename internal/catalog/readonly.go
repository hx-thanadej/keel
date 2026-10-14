package catalog

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/store"
)

// ErrClientOwned refuses a change to a client-owned Cloud Account.
var ErrClientOwned = errors.New("the Cloud Account is client-owned and Keel is read-only there (ADR-0018): remediate by pull request or by hand")

// RequirePlatformOwned is the one guard every flow that writes to a Cloud
// Account calls before the write. It reads ownership at call time, so an
// account flipped to client-owned is refused on the next run whatever
// markers it still carries. The read waits for an uncommitted ownership
// switch. Only grant activation is serialized with it: an Access Grant stays
// requested until its assignment is done, and the switch refuses while one is
// requested or active. Every other flow checks before each write, and a switch
// can land between the check and the call; the next run refuses it. Waste
// cleanup re-checks before each resource it deletes. A refusal
// is recorded as an Activity in its own transaction, so it survives the
// caller's error path, and the error wraps ErrClientOwned.
func RequirePlatformOwned(ctx context.Context, st *store.Store, tenant, accountID, operation string, by activity.Actor) error {
	refused := false
	err := st.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		client, err := IsClientOwned(ctx, tx, accountID)
		if err != nil || !client {
			return err
		}
		refused = true
		_, err = activity.Record(ctx, tx, activity.Activity{
			TenantID: tenant, Source: "keel/catalog", Type: "keel.cloud_account.change_refused",
			Subject: "cloud_account/" + accountID, Operation: operation, Kind: activity.Update, Actor: by,
			Resources: []activity.Resource{{Type: "cloud_account", UID: accountID}},
			Why:       activity.Why{Reason: "ADR-0018"}, Outcome: activity.Failure,
			StatusDetail: operation + " refused: " + ErrClientOwned.Error(),
		})
		return err
	})
	if err != nil {
		return fmt.Errorf("%s: ownership of cloud_account/%s: %w", operation, accountID, err)
	}
	if refused {
		return fmt.Errorf("%s on cloud_account/%s: %w", operation, accountID, ErrClientOwned)
	}
	return nil
}

// ClientOwned is the one selector for jobs that use Keel's own roles in a
// provider's accounts: it reports which of externalIDs are client-owned
// Cloud Accounts in any Tenant, which those roles never reach (ADR-0018).
// An account Keel has not registered is not client-owned.
func ClientOwned(ctx context.Context, st *store.Store, provider string, externalIDs []string) (map[string]bool, error) {
	rows, err := st.AppPool().Query(ctx, `SELECT external_id FROM account_owners($1, $2) WHERE ownership = 'client'`, provider, externalIDs)
	if err != nil {
		return nil, fmt.Errorf("ownership of %s accounts: %w", provider, err)
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, fmt.Errorf("ownership of %s accounts: %w", provider, err)
	}
	out := make(map[string]bool, len(ids))
	for _, id := range ids {
		out[id] = true
	}
	return out, nil
}
