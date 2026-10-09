package catalog_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/hx-thanadej/keel/internal/catalog"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

const (
	awsSecret = "AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	pemKey    = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----"
	wifPool   = "projects/123456789012/locations/global/workloadIdentityPools/keel-pool/providers/keel-oidc"
	gcpSA     = "keel-readonly@client-project.iam.gserviceaccount.com"
	uuidA     = "6f1c1c2e-8a4b-4c5d-9e6f-0a1b2c3d4e5f"
	uuidB     = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
)

// The database refuses what the API refuses, so no writer that bypasses the
// Catalog can store a client-owned account without a well-formed role.
func TestOwnershipInvariantsHoldInTheDatabase(t *testing.T) {
	s := storetest.New(t)
	tenant, err := s.CreateTenant(t.Context(), "tat", "TAT", false)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	insert := func(provider, ownership string, role any) error {
		n++
		return s.InTenant(t.Context(), tenant, func(tx pgx.Tx) error {
			_, err := tx.Exec(t.Context(), `INSERT INTO cloud_accounts (tenant_id, provider, external_id, name, ownership, read_only_role) VALUES ($1, $2, $3, 'x', $4, $5)`,
				tenant, provider, fmt.Sprint(provider, ownership, n), ownership, role)
			return err
		})
	}
	validARN := "arn:aws:iam::123456789012:role/r"
	refused := map[string]error{
		"client without a role":        insert("aws", "client", nil),
		"platform with a role":         insert("tencent", "platform", map[string]string{"role_arn": "a"}),
		"unknown ownership":            insert("aws", "shared", nil),
		"another provider's keys":      insert("azure", "client", map[string]string{"role_arn": validARN}),
		"extra key":                    insert("gcp", "client", map[string]string{"workload_identity_provider": wifPool, "service_account": gcpSA, "key": "k"}),
		"extra key beside a valid one": insert("aws", "client", map[string]string{"role_arn": validARN, "secret_access_key": "k"}),
		"empty value":                  insert("aws", "client", map[string]string{"role_arn": ""}),
		"non-string value":             insert("aws", "client", map[string]any{"role_arn": 1}),
		"json array":                   insert("aws", "client", []string{"role_arn"}),
		"json string":                  insert("aws", "client", `"arn:aws:iam::123456789012:role/r"`),
		"empty object":                 insert("aws", "client", map[string]string{}),
		"json null":                    insert("aws", "client", "null"),
		"nested object":                insert("aws", "client", map[string]any{"role_arn": map[string]string{"role_arn": validARN}}),
		"malformed uuids":              insert("azure", "client", map[string]string{"tenant_id": "t", "client_id": "c"}),
		"aws secret key as role_arn":   insert("aws", "client", map[string]string{"role_arn": awsSecret}),
		"pem as service_account":       insert("gcp", "client", map[string]string{"workload_identity_provider": wifPool, "service_account": pemKey}),
		"whitespace role_arn":          insert("aws", "client", map[string]string{"role_arn": " "}),
	}
	for name, err := range refused {
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "23514" {
			t.Errorf("%s: err = %v, want a check violation", name, err)
		}
	}
	if err := insert("azure", "client", map[string]string{"tenant_id": uuidA, "client_id": uuidB}); err != nil {
		t.Errorf("well-formed azure role refused: %v", err)
	}
}

// checkOwnership and the SQL read_only_role_ok are two copies of one rule.
// This keeps them from drifting.
func TestOwnershipValidatorsAgree(t *testing.T) {
	s := storetest.New(t)
	longPath := strings.Repeat("p/", 520)
	samples := []struct {
		provider string
		role     catalog.ReadOnlyRole
		valid    bool
	}{
		{"tencent", catalog.ReadOnlyRole{RoleARN: "qcs::cam::uin/100012345678:roleName/keel-readonly"}, true},
		{"tencent", catalog.ReadOnlyRole{RoleARN: "qcs::cam::uin/abc:roleName/keel-readonly"}, false},
		{"tencent", catalog.ReadOnlyRole{RoleARN: "qcs::cam::uin/1:roleName/" + strings.Repeat("r", 129)}, false},
		{"aws", catalog.ReadOnlyRole{RoleARN: "arn:aws:iam::123456789012:role/keel-readonly"}, true},
		{"aws", catalog.ReadOnlyRole{RoleARN: "arn:aws-cn:iam::123456789012:role/ops/keel-readonly"}, true},
		{"aws", catalog.ReadOnlyRole{RoleARN: "arn:aws-us-gov:iam::123456789012:role/a/b/keel"}, true},
		{"aws", catalog.ReadOnlyRole{RoleARN: "arn:aws:iam::12345678901:role/r"}, false},
		{"aws", catalog.ReadOnlyRole{RoleARN: "arn:aws:iam::123456789012:user/r"}, false},
		{"aws", catalog.ReadOnlyRole{RoleARN: "arn:aws:iam::123456789012:role/r\n"}, false},
		{"aws", catalog.ReadOnlyRole{RoleARN: "arn:aws:iam::123456789012:role/r\nAKIAIOSFODNN7EXAMPLE"}, false},
		{"aws", catalog.ReadOnlyRole{RoleARN: "arn:aws:iam::123456789012:role/ré"}, false},
		{"aws", catalog.ReadOnlyRole{RoleARN: "arn:aws:iam::123456789012:role/" + longPath + "r"}, false},
		{"aws", catalog.ReadOnlyRole{RoleARN: awsSecret}, false},
		{"aws", catalog.ReadOnlyRole{RoleARN: " "}, false},
		{"aws", catalog.ReadOnlyRole{TenantID: uuidA, ClientID: uuidB}, false},
		{"alibaba", catalog.ReadOnlyRole{RoleARN: "acs:ram::1234567890123456:role/keel-readonly"}, true},
		{"alibaba", catalog.ReadOnlyRole{RoleARN: "acs:ram::1234567890123456:role/keel@readonly"}, false},
		{"azure", catalog.ReadOnlyRole{TenantID: uuidA, ClientID: uuidB}, true},
		{"azure", catalog.ReadOnlyRole{TenantID: strings.ToUpper(uuidA), ClientID: uuidB}, true},
		{"azure", catalog.ReadOnlyRole{TenantID: uuidA, ClientID: uuidB + "0"}, false},
		{"azure", catalog.ReadOnlyRole{TenantID: uuidA}, false},
		{"azure", catalog.ReadOnlyRole{TenantID: uuidA, ClientID: pemKey}, false},
		{"gcp", catalog.ReadOnlyRole{WorkloadIdentityProvider: wifPool, ServiceAccount: gcpSA}, true},
		{"gcp", catalog.ReadOnlyRole{WorkloadIdentityProvider: wifPool, ServiceAccount: pemKey}, false},
		{"gcp", catalog.ReadOnlyRole{WorkloadIdentityProvider: wifPool, ServiceAccount: "keel@client-project.iam.gserviceaccount.com"}, false},
		{"gcp", catalog.ReadOnlyRole{WorkloadIdentityProvider: wifPool, ServiceAccount: "keel-readonly@client-projectXiamXgserviceaccountXcom"}, false},
		{"gcp", catalog.ReadOnlyRole{WorkloadIdentityProvider: "projects/1/locations/us/workloadIdentityPools/keel-pool/providers/keel-oidc", ServiceAccount: gcpSA}, false},
		{"gcp", catalog.ReadOnlyRole{WorkloadIdentityProvider: wifPool, ServiceAccount: gcpSA, RoleARN: "x"}, false},
	}
	for _, c := range samples {
		goOK := catalog.CheckOwnership(c.provider, catalog.OwnershipClient, &c.role) == nil
		raw, err := json.Marshal(c.role)
		if err != nil {
			t.Fatal(err)
		}
		var sqlOK bool
		if err := s.AppPool().QueryRow(t.Context(), `SELECT read_only_role_ok($1, $2::jsonb)`, c.provider, string(raw)).Scan(&sqlOK); err != nil {
			t.Fatal(err)
		}
		if goOK != c.valid || sqlOK != c.valid {
			t.Errorf("%s %s: go = %v, sql = %v, want %v", c.provider, raw, goOK, sqlOK, c.valid)
		}
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
