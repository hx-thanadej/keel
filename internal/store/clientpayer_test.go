package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/hx-thanadej/keel/internal/store"
	"github.com/hx-thanadej/keel/internal/store/storetest"
)

type payerRow struct{ bucket, prefix, region, mode, kms string }

const kmsKey = "arn:aws:kms:us-gov-west-1:300000000001:key/1234abcd-12ab-34cd-56ef-1234567890ab"

// TestClientPayerChecksArePerProvider: the database, not only
// catalog.SetClientPayer, holds each provider's own bucket, region, mode,
// prefix and KMS key rules (keel_app can write those columns directly).
// Migration 00051 survives down and up with rows of both providers present.
func TestClientPayerChecksArePerProvider(t *testing.T) {
	s := storetest.New(t)
	ctx := context.Background()
	su := storetest.Superuser(t, s)
	tenant, err := s.CreateTenant(ctx, "c1", "C1", false)
	if err != nil {
		t.Fatal(err)
	}
	account := map[string]string{}
	for provider, role := range map[string]string{"tencent": "qcs::cam::uin/300000000001:roleName/KeelReadOnly", "aws": "arn:aws-us-gov:iam::300000000001:role/KeelReadOnly"} {
		var id string
		if err := su.QueryRow(ctx, `INSERT INTO cloud_accounts (tenant_id, provider, external_id, name, ownership, read_only_role) VALUES ($1, $2, '300000000001', 'payer', 'client', jsonb_build_object('role_arn', $3::text)) RETURNING id`,
			tenant, provider, role).Scan(&id); err != nil {
			t.Fatal(err)
		}
		account[provider] = id
	}
	insert := func(provider, accountProvider string, r payerRow) error {
		_, err := su.Exec(ctx, `INSERT INTO client_payers (cloud_account_id, tenant_id, provider, bucket, prefix, region, mode, kms_key_arn) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			account[accountProvider], tenant, provider, r.bucket, r.prefix, r.region, r.mode, r.kms)
		return err
	}
	try := func(provider, accountProvider string, r payerRow) error {
		tx, err := su.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		_, err = tx.Exec(ctx, `INSERT INTO client_payers (cloud_account_id, tenant_id, provider, bucket, prefix, region, mode, kms_key_arn) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			account[accountProvider], tenant, provider, r.bucket, r.prefix, r.region, r.mode, r.kms)
		return err
	}
	tencentOK := payerRow{"c1-bills-1250000001", "focus/", "ap-bangkok", "per-day", ""}
	awsOK := payerRow{"c1.bills-2026", "exports/focus", "us-gov-west-1", "export-folder", kmsKey}

	refused := map[string]struct {
		provider string
		row      payerRow
	}{
		"tencent bucket without appid":  {"tencent", payerRow{"plain-bucket", "", "ap-bangkok", "cumulative", ""}},
		"tencent dotted bucket":         {"tencent", payerRow{"a.b.c", "", "ap-bangkok", "cumulative", ""}},
		"tencent export-folder mode":    {"tencent", payerRow{"c1-bills-1250000001", "", "ap-bangkok", "export-folder", ""}},
		"tencent three-part region":     {"tencent", payerRow{"c1-bills-1250000001", "", "us-gov-west-1", "cumulative", ""}},
		"tencent kms key":               {"tencent", payerRow{"c1-bills-1250000001", "", "ap-bangkok", "cumulative", kmsKey}},
		"tencent uppercase bucket":      {"tencent", payerRow{"Bills-1250000001", "", "ap-bangkok", "cumulative", ""}},
		"tencent bogus mode":            {"tencent", payerRow{"c1-bills-1250000001", "", "ap-bangkok", "bogus", ""}},
		"aws per-day mode":              {"aws", payerRow{"c1-bills", "", "us-east-1", "per-day", ""}},
		"aws cumulative mode":           {"aws", payerRow{"c1-bills", "", "us-east-1", "cumulative", ""}},
		"aws uppercase bucket":          {"aws", payerRow{"C1-bills", "", "us-east-1", "export-folder", ""}},
		"aws bucket with slash":         {"aws", payerRow{"c1/bills", "", "us-east-1", "export-folder", ""}},
		"aws bucket with dot-dot":       {"aws", payerRow{"c1..bills", "", "us-east-1", "export-folder", ""}},
		"aws bucket ../":                {"aws", payerRow{"../", "", "us-east-1", "export-folder", ""}},
		"aws 1-char bucket":             {"aws", payerRow{"a", "", "us-east-1", "export-folder", ""}},
		"aws IP bucket":                 {"aws", payerRow{"192.168.1.1", "", "us-east-1", "export-folder", ""}},
		"aws xn-- bucket":               {"aws", payerRow{"xn--bills", "", "us-east-1", "export-folder", ""}},
		"aws access point alias":        {"aws", payerRow{"bills-s3alias", "", "us-east-1", "export-folder", ""}},
		"aws region with underscore":    {"aws", payerRow{"c1-bills", "", "us_east_1", "export-folder", ""}},
		"aws Tencent region":            {"aws", payerRow{"c1-bills", "", "ap-bangkok", "export-folder", ""}},
		"aws wildcard prefix":           {"aws", payerRow{"c1-bills", "exports/*", "us-east-1", "export-folder", ""}},
		"aws policy variable prefix":    {"aws", payerRow{"c1-bills", "${aws:username}/", "us-east-1", "export-folder", ""}},
		"aws kms alias":                 {"aws", payerRow{"c1-bills", "", "us-east-1", "export-folder", "arn:aws:kms:us-east-1:300000000001:alias/bills"}},
		"aws kms key in another region": {"aws", payerRow{"c1-bills", "", "us-east-1", "export-folder", "arn:aws:kms:us-west-2:300000000001:key/1234abcd-12ab-34cd-56ef-1234567890ab"}},
		"aws kms wildcard":              {"aws", payerRow{"c1-bills", "", "us-east-1", "export-folder", "arn:aws:kms:us-east-1:300000000001:key/*"}},
		"aws row on a tencent account":  {"aws", payerRow{"c1-bills", "", "us-east-1", "export-folder", ""}},
		"tencent row on an aws account": {"tencent", tencentOK},
	}
	for name, c := range refused {
		accountProvider := c.provider
		switch name {
		case "aws row on a tencent account":
			accountProvider = "tencent"
		case "tencent row on an aws account":
			accountProvider = "aws"
		}
		var pgErr *pgconn.PgError
		if err := try(c.provider, accountProvider, c.row); !errors.As(err, &pgErr) || (pgErr.Code != "23514" && pgErr.Code != "23503") {
			t.Errorf("%s: insert = %v, want a check or foreign key violation", name, err)
		}
	}
	for name, c := range map[string]struct {
		provider string
		row      payerRow
	}{
		"tencent per-day":       {"tencent", tencentOK},
		"tencent cumulative":    {"tencent", payerRow{"c1-bills-1250000001", "", "ap-singapore", "cumulative", ""}},
		"tencent no bucket yet": {"tencent", payerRow{"", "", "ap-bangkok", "cumulative", ""}},
		"aws with kms":          {"aws", awsOK},
		"aws no bucket yet":     {"aws", payerRow{"", "", "us-east-1", "export-folder", ""}},
		"aws mrk key":           {"aws", payerRow{"c1-bills", "", "eu-west-1", "export-folder", "arn:aws:kms:eu-west-1:300000000001:key/mrk-1234abcd12ab34cd56ef1234567890ab"}},
	} {
		if err := try(c.provider, c.provider, c.row); err != nil {
			t.Errorf("%s: insert = %v, want accepted", name, err)
		}
	}

	if err := insert("tencent", "tencent", tencentOK); err != nil {
		t.Fatal(err)
	}
	if err := insert("aws", "aws", awsOK); err != nil {
		t.Fatal(err)
	}
	g, err := goose.NewProvider(goose.DialectPostgres, stdlib.OpenDB(*su.Config()), store.Migrations)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.DownTo(ctx, 50); err != nil {
		t.Fatalf("down to 00050 with rows of both providers: %v", err)
	}
	var buckets []string
	rows, err := su.Query(ctx, `SELECT bucket FROM client_payers`)
	if err != nil {
		t.Fatal(err)
	}
	if buckets, err = pgx.CollectRows(rows, pgx.RowTo[string]); err != nil || len(buckets) != 1 || buckets[0] != tencentOK.bucket {
		t.Fatalf("after down: client_payers buckets %v, %v; want only the Tencent row", buckets, err)
	}
	if _, err := su.Exec(ctx, `UPDATE client_payers SET bucket = 'plain-bucket'`); err == nil {
		t.Error("after down: a Tencent bucket without appid was accepted")
	}
	if _, err := g.Up(ctx); err != nil {
		t.Fatalf("up again: %v", err)
	}
	var provider string
	if err := su.QueryRow(ctx, `SELECT provider FROM client_payers WHERE cloud_account_id = $1`, account["tencent"]).Scan(&provider); err != nil || provider != "tencent" {
		t.Errorf("after up: Tencent row provider %q, %v", provider, err)
	}
	if err := insert("aws", "aws", awsOK); err != nil {
		t.Errorf("after up: AWS row refused: %v", err)
	}
	if err := try("tencent", "tencent", payerRow{"plain-bucket", "", "ap-bangkok", "cumulative", ""}); err == nil {
		t.Error("after up: a Tencent bucket without appid was accepted")
	}
}

// TestRoleExternalIDIsWritableOnlyInItsTenant: keel_app may write a payer's
// role_external_id (rotation, #213), but row security keeps another Tenant
// from touching it and the 32-hex check still holds. keel_app still cannot
// move a payer to another account or Tenant.
func TestRoleExternalIDIsWritableOnlyInItsTenant(t *testing.T) {
	s := storetest.New(t)
	ctx := context.Background()
	su := storetest.Superuser(t, s)
	tat, err := s.CreateTenant(ctx, "tat", "TAT", false)
	if err != nil {
		t.Fatal(err)
	}
	other, err := s.CreateTenant(ctx, "other", "Other", false)
	if err != nil {
		t.Fatal(err)
	}
	var account, ext string
	if err := su.QueryRow(ctx, `INSERT INTO cloud_accounts (tenant_id, provider, external_id, name, ownership, read_only_role) VALUES ($1, 'tencent', '300000000001', 'payer', 'client', '{"role_arn": "qcs::cam::uin/300000000001:roleName/KeelReadOnly"}') RETURNING id`, tat).Scan(&account); err != nil {
		t.Fatal(err)
	}
	if err := su.QueryRow(ctx, `INSERT INTO client_payers (cloud_account_id, tenant_id, provider, region) VALUES ($1, $2, 'tencent', 'ap-bangkok') RETURNING role_external_id`, account, tat).Scan(&ext); err != nil {
		t.Fatal(err)
	}
	const fresh = "0123456789abcdef0123456789abcdef"
	update := func(tenant, sql string, args ...any) (int64, error) {
		var n int64
		err := s.InTenant(ctx, tenant, func(tx pgx.Tx) error {
			tag, err := tx.Exec(ctx, sql, args...)
			n = tag.RowsAffected()
			return err
		})
		return n, err
	}
	if n, err := update(other, `UPDATE client_payers SET role_external_id = $1 WHERE cloud_account_id = $2`, fresh, account); err != nil || n != 0 {
		t.Errorf("another Tenant's update = %d rows, %v; want 0 rows", n, err)
	}
	var pgErr *pgconn.PgError
	if _, err := update(tat, `UPDATE client_payers SET role_external_id = 'chosen-by-hand' WHERE cloud_account_id = $1`, account); !errors.As(err, &pgErr) || pgErr.Code != "23514" {
		t.Errorf("non-hex role_external_id = %v, want a check violation", err)
	}
	for _, col := range []string{"tenant_id", "cloud_account_id", "provider"} {
		if _, err := update(tat, `UPDATE client_payers SET `+col+` = `+col+` WHERE cloud_account_id = $1`, account); !errors.As(err, &pgErr) || pgErr.Code != "42501" {
			t.Errorf("keel_app update of %s = %v, want insufficient privilege", col, err)
		}
	}
	if n, err := update(tat, `UPDATE client_payers SET role_external_id = $1 WHERE cloud_account_id = $2`, fresh, account); err != nil || n != 1 {
		t.Fatalf("own Tenant's rotation = %d rows, %v", n, err)
	}
	var got string
	if err := su.QueryRow(ctx, `SELECT role_external_id FROM client_payers WHERE cloud_account_id = $1`, account).Scan(&got); err != nil || got != fresh {
		t.Errorf("role_external_id = %q, %v; want %q (was %q)", got, err, fresh, ext)
	}
}
