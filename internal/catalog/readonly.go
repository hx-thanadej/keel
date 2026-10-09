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
// markers it still carries. A refusal is recorded as an Activity in its own
// transaction, so it survives the caller's error path, and the error wraps
// ErrClientOwned.
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
