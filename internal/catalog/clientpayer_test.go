package catalog_test

import (
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/auth"
	"github.com/hx-thanadej/keel/internal/authz"
	"github.com/hx-thanadej/keel/internal/catalog"
	"github.com/hx-thanadej/keel/internal/store"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

type payerWorld struct {
	s                *store.Store
	c                *catalog.Service
	home, tat, other string
}

func newPayerWorld(t *testing.T) payerWorld {
	t.Helper()
	s := storetest.New(t)
	az, err := authz.New()
	if err != nil {
		t.Fatal(err)
	}
	w := payerWorld{s: s, c: catalog.New(s, az)}
	for slug, id := range map[string]*string{"harmonyx": &w.home, "tat": &w.tat, "other": &w.other} {
		if *id, err = s.CreateTenant(t.Context(), slug, slug, slug == "harmonyx"); err != nil {
			t.Fatal(err)
		}
	}
	return w
}

func (w payerWorld) admin(tenants ...string) auth.Principal {
	p := auth.Principal{Subject: "user:admin@harmonyx.co", Kind: auth.KindHuman, TenantID: w.home, Home: true}
	for _, tenant := range tenants {
		p.Bindings = append(p.Bindings, auth.Binding{Role: auth.RolePlatformAdmin, TenantID: tenant})
	}
	return p
}

func (w payerWorld) storedExternalID(t *testing.T, tenant, account string) string {
	t.Helper()
	var ext string
	if err := w.s.InTenant(t.Context(), tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(t.Context(), `SELECT role_external_id FROM client_payers WHERE cloud_account_id = $1`, account).Scan(&ext)
	}); err != nil {
		t.Fatal(err)
	}
	return ext
}

func (w payerWorld) payer(t *testing.T, tenant, ext string) (account, externalID string) {
	t.Helper()
	p := w.admin(tenant)
	a, err := w.c.CreateCloudAccount(t.Context(), p, tenant, nil, "tencent", ext, "payer", catalog.OwnershipClient,
		&catalog.ReadOnlyRole{RoleARN: "qcs::cam::uin/" + ext + ":roleName/KeelReadOnly"}, "client payer")
	if err != nil {
		t.Fatal(err)
	}
	out, err := w.c.SetClientPayer(t.Context(), p, tenant, a.ID, catalog.ClientPayer{}, "pays its own bill")
	if err != nil {
		t.Fatal(err)
	}
	return a.ID, out.RoleExternalID
}

var hex32 = regexp.MustCompile(`^[0-9a-f]{32}$`)

// TestRotateClientPayerExternalID: a platform admin of the payer's Tenant
// gets a new ExternalId exactly once. The old one stops being Keel's, the
// rotation is an Activity that never carries either value, and nobody else
// (another role, another Tenant's admin, an archived payer) can rotate.
func TestRotateClientPayerExternalID(t *testing.T) {
	w := newPayerWorld(t)
	ctx := t.Context()
	account, old := w.payer(t, w.tat, "100000000001")

	out, err := w.c.RotateClientPayerExternalID(ctx, w.admin(w.tat), w.tat, account, "operator lost the first id")
	if err != nil {
		t.Fatal(err)
	}
	if !hex32.MatchString(out.RoleExternalID) || out.RoleExternalID == old {
		t.Fatalf("rotated role_external_id %q (old %q), want a new 32-hex id", out.RoleExternalID, old)
	}
	if got := w.storedExternalID(t, w.tat, account); got != out.RoleExternalID {
		t.Errorf("stored role_external_id %q, want the rotated %q; the old id must be gone", got, out.RoleExternalID)
	}
	again, err := w.c.SetClientPayer(ctx, w.admin(w.tat), w.tat, account, catalog.ClientPayer{Bucket: "tat-bills-1250000001"}, "delivery set up")
	if err != nil {
		t.Fatal(err)
	}
	if again.RoleExternalID != "" {
		t.Errorf("SetClientPayer after rotation shows the id again: %q", again.RoleExternalID)
	}

	acts, err := w.c.ListActivities(ctx, w.admin(w.tat), w.tat, activity.Filter{})
	if err != nil {
		t.Fatal(err)
	}
	rotated := 0
	for _, a := range acts {
		if a.Type == "keel.cloud_account.client_payer_external_id_rotated" {
			rotated++
		}
		for _, id := range []string{old, out.RoleExternalID} {
			if strings.Contains(string(a.Event), id) {
				t.Errorf("Activity %s carries an ExternalId: %s", a.Type, a.Event)
			}
		}
	}
	if rotated != 1 {
		t.Errorf("rotation Activities = %d, want 1", rotated)
	}

	for name, p := range map[string]auth.Principal{
		"finops lead":          {Subject: "user:f@tat", Kind: auth.KindHuman, TenantID: w.tat, Bindings: []auth.Binding{{Role: auth.RoleFinOpsLead, TenantID: w.tat}}},
		"tenant viewer":        {Subject: "user:v@tat", Kind: auth.KindHuman, TenantID: w.tat, Bindings: []auth.Binding{{Role: auth.RoleTenantViewer, TenantID: w.tat}}},
		"other Tenant's admin": w.admin(w.other),
		"home admin, unbound":  w.admin(w.home),
	} {
		if _, err := w.c.RotateClientPayerExternalID(ctx, p, w.tat, account, "x"); !errors.Is(err, catalog.ErrForbidden) {
			t.Errorf("%s: rotate = %v, want ErrForbidden", name, err)
		}
	}
	if _, err := w.c.RotateClientPayerExternalID(ctx, w.admin(w.other), w.other, account, "x"); !errors.Is(err, catalog.ErrNotFound) {
		t.Errorf("other Tenant's admin naming TAT's payer under its own Tenant: rotate = %v, want ErrNotFound", err)
	}
	if got := w.storedExternalID(t, w.tat, account); got != out.RoleExternalID {
		t.Errorf("a refused rotation changed the id to %q", got)
	}

	if _, err := w.c.ArchiveCloudAccount(ctx, w.admin(w.tat), w.tat, account, "client left"); err != nil {
		t.Fatal(err)
	}
	if _, err := w.c.RotateClientPayerExternalID(ctx, w.admin(w.tat), w.tat, account, "x"); !errors.Is(err, catalog.ErrNotFound) {
		t.Errorf("rotate an archived payer = %v, want ErrNotFound", err)
	}
	notPayer, err := w.c.CreateCloudAccount(ctx, w.admin(w.tat), w.tat, nil, "tencent", "100000000009", "member", catalog.OwnershipClient,
		&catalog.ReadOnlyRole{RoleARN: "qcs::cam::uin/100000000009:roleName/KeelReadOnly"}, "member")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.c.RotateClientPayerExternalID(ctx, w.admin(w.tat), w.tat, notPayer.ID, "x"); !errors.Is(err, catalog.ErrNotFound) {
		t.Errorf("rotate an account that is no payer = %v, want ErrNotFound", err)
	}
}

// TestReonboardArchivedPayer: an archived payer comes back by an audited
// unarchive, keeping its id, history and client ownership. Registering it
// again while it exists, archived or not, still conflicts, so no two
// accounts ever share (provider, external_id).
func TestReonboardArchivedPayer(t *testing.T) {
	w := newPayerWorld(t)
	ctx := t.Context()
	account, ext := w.payer(t, w.tat, "100000000001")
	role := &catalog.ReadOnlyRole{RoleARN: "qcs::cam::uin/100000000001:roleName/KeelReadOnly"}
	register := func(tenant string) error {
		_, err := w.c.CreateCloudAccount(ctx, w.admin(tenant), tenant, nil, "tencent", "100000000001", "payer", catalog.OwnershipClient, role, "again")
		return err
	}
	if _, err := w.c.ArchiveCloudAccount(ctx, w.admin(w.tat), w.tat, account, "client left"); err != nil {
		t.Fatal(err)
	}
	if err := register(w.tat); !errors.Is(err, catalog.ErrConflict) {
		t.Errorf("register an archived payer again = %v, want ErrConflict (unarchive instead)", err)
	}

	for name, p := range map[string]auth.Principal{
		"finops lead":          {Subject: "user:f@tat", Kind: auth.KindHuman, TenantID: w.tat, Bindings: []auth.Binding{{Role: auth.RoleFinOpsLead, TenantID: w.tat}}},
		"other Tenant's admin": w.admin(w.other),
	} {
		if _, err := w.c.UnarchiveCloudAccount(ctx, p, w.tat, account, "x"); !errors.Is(err, catalog.ErrForbidden) {
			t.Errorf("%s: unarchive = %v, want ErrForbidden", name, err)
		}
	}
	if _, err := w.c.UnarchiveCloudAccount(ctx, w.admin(w.other), w.other, account, "x"); !errors.Is(err, catalog.ErrNotFound) {
		t.Errorf("other Tenant's admin naming TAT's account under its own Tenant: unarchive = %v, want ErrNotFound", err)
	}

	a, err := w.c.UnarchiveCloudAccount(ctx, w.admin(w.tat), w.tat, account, "client is back")
	if err != nil {
		t.Fatal(err)
	}
	if a.ID != account || a.ArchivedAt != nil || a.Ownership != catalog.OwnershipClient || a.ReadOnlyRole == nil {
		t.Errorf("unarchived account = %+v, want the same active client-owned account", a)
	}
	if got := w.storedExternalID(t, w.tat, account); got != ext {
		t.Errorf("unarchive changed role_external_id to %q", got)
	}
	if _, err := w.c.UnarchiveCloudAccount(ctx, w.admin(w.tat), w.tat, account, "again"); err != nil {
		t.Errorf("unarchive an active account = %v, want a no-op", err)
	}
	if err := register(w.tat); !errors.Is(err, catalog.ErrConflict) {
		t.Errorf("register a second active payer = %v, want ErrConflict", err)
	}
	if err := register(w.other); !errors.Is(err, catalog.ErrConflict) {
		t.Errorf("register TAT's payer in another Tenant = %v, want ErrConflict", err)
	}
	if err := catalog.RequirePlatformOwned(ctx, w.s, w.tat, account, "baseline", activity.Actor{Type: activity.ActorHuman, UID: "user:x"}); !errors.Is(err, catalog.ErrClientOwned) {
		t.Errorf("RequirePlatformOwned on the unarchived payer = %v, want ErrClientOwned", err)
	}
	if _, err := w.c.RotateClientPayerExternalID(ctx, w.admin(w.tat), w.tat, account, "re-onboarding"); err != nil {
		t.Errorf("rotate the unarchived payer = %v", err)
	}

	acts, err := w.c.ListActivities(ctx, w.admin(w.tat), w.tat, activity.Filter{Type: "keel.cloud_account.unarchived"})
	if err != nil {
		t.Fatal(err)
	}
	if len(acts) != 2 {
		t.Errorf("unarchive Activities = %d, want 2", len(acts))
	}
}
