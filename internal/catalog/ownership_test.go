package catalog_test

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/hx-thanadej/keel/internal/catalog"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

// The database refuses what the API refuses, so no writer that bypasses the
// Catalog can store a client-owned account without its read-only role.
func TestOwnershipInvariantsHoldInTheDatabase(t *testing.T) {
	s := storetest.New(t)
	tenant, err := s.CreateTenant(t.Context(), "tat", "TAT", false)
	if err != nil {
		t.Fatal(err)
	}
	insert := func(provider, ownership string, role any) error {
		return s.InTenant(t.Context(), tenant, func(tx pgx.Tx) error {
			_, err := tx.Exec(t.Context(), `INSERT INTO cloud_accounts (tenant_id, provider, external_id, name, ownership, read_only_role) VALUES ($1, $2, $3, 'x', $4, $5)`,
				tenant, provider, provider+ownership+"-"+t.Name(), ownership, role)
			return err
		})
	}
	refused := map[string]error{
		"client without a role":      insert("aws", "client", nil),
		"platform with a role":       insert("tencent", "platform", map[string]string{"role_arn": "a"}),
		"unknown ownership":          insert("aws", "shared", nil),
		"another provider's keys":    insert("azure", "client", map[string]string{"role_arn": "a"}),
		"extra key":                  insert("gcp", "client", map[string]string{"workload_identity_provider": "p", "service_account": "s", "key": "k"}),
		"empty value":                insert("aws", "client", map[string]string{"role_arn": ""}),
		"non-string value":           insert("aws", "client", map[string]any{"role_arn": 1}),
		"role that is not an object": insert("aws", "client", []string{"role_arn"}),
	}
	for name, err := range refused {
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "23514" {
			t.Errorf("%s: err = %v, want a check violation", name, err)
		}
	}
	if err := insert("azure", "client", map[string]string{"tenant_id": "t", "client_id": "c"}); err != nil {
		t.Errorf("well-shaped azure role refused: %v", err)
	}
}

func TestIsClientOwned(t *testing.T) {
	s := storetest.New(t)
	tenant, err := s.CreateTenant(t.Context(), "tat", "TAT", false)
	if err != nil {
		t.Fatal(err)
	}
	var ours, theirs string
	err = s.InTenant(t.Context(), tenant, func(tx pgx.Tx) error {
		if err := tx.QueryRow(t.Context(), `INSERT INTO cloud_accounts (tenant_id, provider, external_id, name) VALUES ($1, 'aws', '111111111111', 'ours') RETURNING id::text`, tenant).Scan(&ours); err != nil {
			return err
		}
		return tx.QueryRow(t.Context(), `INSERT INTO cloud_accounts (tenant_id, provider, external_id, name, ownership, read_only_role)
			VALUES ($1, 'aws', '222222222222', 'theirs', 'client', '{"role_arn": "arn:aws:iam::222222222222:role/keel-readonly"}') RETURNING id::text`, tenant).Scan(&theirs)
	})
	if err != nil {
		t.Fatal(err)
	}
	err = s.InTenant(t.Context(), tenant, func(tx pgx.Tx) error {
		for id, want := range map[string]bool{ours: false, theirs: true} {
			got, err := catalog.IsClientOwned(t.Context(), tx, id)
			if err != nil || got != want {
				t.Errorf("IsClientOwned(%s) = %v, %v; want %v", id, got, err, want)
			}
		}
		if _, err := catalog.IsClientOwned(t.Context(), tx, "00000000-0000-4000-8000-000000000000"); !errors.Is(err, catalog.ErrNotFound) {
			t.Errorf("missing account: err = %v, want ErrNotFound", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	other, err := s.CreateTenant(t.Context(), "acme", "Acme", false)
	if err != nil {
		t.Fatal(err)
	}
	err = s.InTenant(t.Context(), other, func(tx pgx.Tx) error {
		if _, err := catalog.IsClientOwned(t.Context(), tx, theirs); !errors.Is(err, catalog.ErrNotFound) {
			t.Errorf("another Tenant's account: err = %v, want ErrNotFound", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
