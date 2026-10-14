package catalog_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/catalog"
	"github.com/hx-thanadej/keel/internal/store"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

const (
	keelAccount   = "200000000031"
	clientAccount = "300000000031"
	unregistered  = "200000000099"
	clientRoleARN = "qcs::cam::uin/" + clientAccount + ":roleName/KeelReadOnly"
)

type roleWorld struct {
	st                  *store.Store
	home, client, other string
}

func newRoleWorld(t *testing.T) roleWorld {
	t.Helper()
	ctx := context.Background()
	w := roleWorld{st: storetest.New(t)}
	var err error
	for slug, id := range map[string]*string{"home": &w.home, "client": &w.client, "other": &w.other} {
		if *id, err = w.st.CreateTenant(ctx, slug, slug, slug == "home"); err != nil {
			t.Fatal(err)
		}
	}
	w.exec(t, w.home, `INSERT INTO cloud_accounts (tenant_id, provider, external_id, name) VALUES (current_tenant_id(), 'tencent', $1, 'platform')`, keelAccount)
	w.exec(t, w.client, `WITH a AS (INSERT INTO cloud_accounts (tenant_id, provider, external_id, name, ownership, read_only_role)
		VALUES (current_tenant_id(), 'tencent', $1, 'payer', 'client', jsonb_build_object('role_arn', $2::text)) RETURNING id)
		INSERT INTO client_payers (cloud_account_id, tenant_id, provider, region) SELECT id, current_tenant_id(), 'tencent', 'ap-bangkok' FROM a`, clientAccount, clientRoleARN)
	return w
}

func (w roleWorld) exec(t *testing.T, tenant, sql string, args ...any) {
	t.Helper()
	if err := w.st.InTenant(context.Background(), tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), sql, args...)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// TestKeelAccountRefusesClientOwnedAccounts: Keel's own role reaches a
// platform-owned or unregistered account and never a client-owned one,
// live or archived; the zero KeelAccount, which no check built, reaches
// nothing.
func TestKeelAccountRefusesClientOwnedAccounts(t *testing.T) {
	w := newRoleWorld(t)
	ctx := context.Background()
	for account, refused := range map[string]bool{keelAccount: false, unregistered: false, clientAccount: true} {
		a, err := catalog.ReachKeelAccount(ctx, w.st, "tencent", account)
		if got := errors.Is(err, catalog.ErrClientOwned); got != refused || (!refused && err != nil) {
			t.Errorf("ReachKeelAccount(%s) = %v, want refused=%v", account, err, refused)
		}
		if !refused && a.ID() != account {
			t.Errorf("ReachKeelAccount(%s).ID() = %q", account, a.ID())
		}
	}
	if _, err := catalog.ReachKeelAccount(ctx, w.st, "aws", clientAccount); err != nil {
		t.Errorf("the same id on another provider is not the client's account: %v", err)
	}

	ran := false
	if err := (catalog.KeelAccount{}).Enter(ctx, func() error { ran = true; return nil }); err == nil || ran {
		t.Errorf("zero KeelAccount: err %v, assumed %v; want refused before assuming", err, ran)
	}

	w.exec(t, w.client, `UPDATE cloud_accounts SET archived_at = now() WHERE external_id = $1`, clientAccount)
	if _, err := catalog.ReachKeelAccount(ctx, w.st, "tencent", clientAccount); !errors.Is(err, catalog.ErrClientOwned) {
		t.Errorf("archived client-owned account: %v, want refused", err)
	}
}

// TestKeelRoleWaitsForAnOwnershipSwitch: an ownership switch in flight
// when Keel's role is assumed holds the assumption until it commits, and
// the assumption is then refused; it never reaches STS.
func TestKeelRoleWaitsForAnOwnershipSwitch(t *testing.T) {
	w := newRoleWorld(t)
	ctx := context.Background()
	a, err := catalog.ReachKeelAccount(ctx, w.st, "tencent", keelAccount)
	if err != nil {
		t.Fatal(err)
	}
	switched, commit, switchDone := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		switchDone <- w.st.InTenant(ctx, w.home, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `UPDATE cloud_accounts SET ownership = 'client', read_only_role = jsonb_build_object('role_arn', 'qcs::cam::uin/'||external_id||':roleName/R') WHERE external_id = $1`, keelAccount); err != nil {
				close(switched)
				return err
			}
			close(switched)
			<-commit
			return nil
		})
	}()
	<-switched
	assumed, entered := make(chan struct{}, 1), make(chan error, 1)
	go func() { entered <- a.Enter(ctx, func() error { assumed <- struct{}{}; return nil }) }()
	select {
	case err = <-entered:
		t.Errorf("Enter returned %v while the switch was in flight; want it to wait", err)
		close(commit)
	case <-time.After(300 * time.Millisecond):
		close(commit)
		err = <-entered
	}
	if err := <-switchDone; err != nil {
		t.Fatal(err)
	}
	if !errors.Is(err, catalog.ErrClientOwned) {
		t.Fatalf("Enter after the switch committed = %v, want ErrClientOwned", err)
	}
	if len(assumed) != 0 {
		t.Fatal("Keel's role was assumed in an account that became client-owned")
	}
}

// TestOwnershipSwitchWaitsForKeelRole: a switch to client-owned, or a new
// client-owned registration of the account, waits while Keel's role is
// being assumed there, so it never lands between the check and STS.
func TestOwnershipSwitchWaitsForKeelRole(t *testing.T) {
	for name, sql := range map[string]string{
		"switch":   `UPDATE cloud_accounts SET ownership = 'client', read_only_role = jsonb_build_object('role_arn', 'qcs::cam::uin/'||external_id||':roleName/R') WHERE external_id = $1`,
		"register": `INSERT INTO cloud_accounts (tenant_id, provider, external_id, name, ownership, read_only_role) VALUES (current_tenant_id(), 'tencent', $1, 'dup', 'client', jsonb_build_object('role_arn', 'qcs::cam::uin/'||$1||':roleName/R'))`,
	} {
		t.Run(name, func(t *testing.T) {
			w := newRoleWorld(t)
			ctx := context.Background()
			account := map[string]string{"switch": keelAccount, "register": unregistered}[name]
			a, err := catalog.ReachKeelAccount(ctx, w.st, "tencent", account)
			if err != nil {
				t.Fatal(err)
			}
			inSTS, release, entered := make(chan struct{}), make(chan struct{}), make(chan error, 1)
			go func() {
				entered <- a.Enter(ctx, func() error { close(inSTS); <-release; return nil })
			}()
			<-inSTS
			tenant := w.home
			if name == "register" {
				tenant = w.other
			}
			switchDone := make(chan error, 1)
			go func() {
				switchDone <- w.st.InTenant(ctx, tenant, func(tx pgx.Tx) error {
					_, err := tx.Exec(ctx, sql, account)
					return err
				})
			}()
			select {
			case err = <-switchDone:
				t.Errorf("%s committed (%v) while Keel's role was being assumed; want it to wait", name, err)
				close(release)
			case <-time.After(300 * time.Millisecond):
				close(release)
				err = <-switchDone
			}
			if err := <-entered; err != nil {
				t.Errorf("Enter = %v, want the assumption that started first to finish", err)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := catalog.ReachKeelAccount(ctx, w.st, "tencent", account); !errors.Is(err, catalog.ErrClientOwned) {
				t.Fatalf("after the %s: %v, want ErrClientOwned", name, err)
			}
		})
	}
}

// TestClientReadRoleComesFromTheRegistration: a client's read role is the
// role and ExternalId the payer's registration holds in that Tenant, and
// nothing else: not a platform-owned account, not another Tenant's payer,
// not an unregistered one.
func TestClientReadRoleComesFromTheRegistration(t *testing.T) {
	w := newRoleWorld(t)
	ctx := context.Background()
	r, err := catalog.LoadClientReadRole(ctx, w.st, "tencent", w.client, clientAccount)
	if err != nil {
		t.Fatal(err)
	}
	var stored string
	if err := w.st.InTenant(ctx, w.client, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT role_external_id FROM client_payers`).Scan(&stored)
	}); err != nil {
		t.Fatal(err)
	}
	if r.Payer() != clientAccount || r.ARN() != clientRoleARN || r.ExternalID() != stored || len(stored) != 32 {
		t.Errorf("client read role = %s %s %s, want %s %s %s", r.Payer(), r.ARN(), r.ExternalID(), clientAccount, clientRoleARN, stored)
	}
	for name, tc := range map[string]struct{ provider, tenant, payer string }{
		"platform-owned": {"tencent", w.home, keelAccount},
		"other tenant":   {"tencent", w.other, clientAccount},
		"other provider": {"aws", w.client, clientAccount},
		"unregistered":   {"tencent", w.client, unregistered},
	} {
		if _, err := catalog.LoadClientReadRole(ctx, w.st, tc.provider, tc.tenant, tc.payer); err == nil {
			t.Errorf("%s: a client read role was built", name)
		}
	}
}
