package cost_test

import (
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/cost"
)

type clientTenant struct {
	id, payer, member, payerAccount string
}

// clientRoles is each provider's read-only role ARN for an account.
var clientRoles = map[string]func(account string) string{
	"tencent": func(a string) string { return "qcs::cam::uin/" + a + ":roleName/KeelReadOnly" },
	"aws":     func(a string) string { return "arn:aws:iam::" + a + ":role/KeelReadOnly" },
}

// addClient registers a Tenant with a client-owned payer and member account
// on provider, and marks the payer as a client payer delivering to bucket.
func addClient(t *testing.T, w world, provider, slug, payer, member, bucket string) clientTenant {
	t.Helper()
	ctx := context.Background()
	c := clientTenant{payer: payer, member: member}
	var err error
	c.id, err = w.s.CreateTenant(ctx, slug, slug, false)
	must(t, err)
	must(t, w.s.InTenant(ctx, c.id, func(tx pgx.Tx) error {
		var team, project, env string
		if err := tx.QueryRow(ctx, `INSERT INTO teams (tenant_id, slug, name) VALUES ($1, 'ops', 'Ops') RETURNING id`, c.id).Scan(&team); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO projects (tenant_id, team_id, slug, name) VALUES ($1, $2, $3, 'Shop') RETURNING id`, c.id, team, slug+"-shop").Scan(&project); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO environments (tenant_id, project_id, name) VALUES ($1, $2, 'prod') RETURNING id`, c.id, project).Scan(&env); err != nil {
			return err
		}
		role := func(account string) string { return `{"role_arn": "` + clientRoles[provider](account) + `"}` }
		if err := tx.QueryRow(ctx, `INSERT INTO cloud_accounts (tenant_id, provider, external_id, name, ownership, read_only_role) VALUES ($1, $2, $3, 'payer', 'client', $4) RETURNING id`,
			c.id, provider, payer, role(payer)).Scan(&c.payerAccount); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO cloud_accounts (tenant_id, environment_id, provider, external_id, name, ownership, read_only_role) VALUES ($1, $2, $3, $4, 'shop-prod', 'client', $5)`,
			c.id, env, provider, member, role(member)); err != nil {
			return err
		}
		delivery := map[string][3]string{"tencent": {"ap-bangkok", "per-day", "focus/"}, "aws": {"us-east-1", "export-folder", "focus"}}[provider]
		_, err := tx.Exec(ctx, `INSERT INTO client_payers (cloud_account_id, tenant_id, provider, bucket, prefix, region, mode) VALUES ($1, $2, $3, $4, $7, $5, $6)`,
			c.payerAccount, c.id, provider, bucket, delivery[0], delivery[1], delivery[2])
		return err
	}))
	return c
}

type billRow struct{ sub, cost, tags string }

// bill writes a minimal Tencent FOCUS file for payer, all lines on 2026-09-01.
func bill(t *testing.T, payer string, rows ...billRow) []byte {
	t.Helper()
	out := [][]string{{"BilledCost", "EffectiveCost", "BillingAccountId", "BillingCurrency", "BillingPeriodStart", "BillingPeriodEnd",
		"ChargeCategory", "ChargePeriodStart", "ChargePeriodEnd", "ServiceName", "SubAccountId", "Tags"}}
	for _, r := range rows {
		tags := r.tags
		if tags == "" {
			tags = "{}"
		}
		out = append(out, []string{r.cost, r.cost, payer, "USD", "2026-09-01T00:00:00Z", "2026-10-01T00:00:00Z",
			"Usage", "2026-09-01T00:00:00Z", "2026-09-02T00:00:00Z", "Cloud Virtual Machine", r.sub, tags})
	}
	var buf bytes.Buffer
	must(t, csv.NewWriter(&buf).WriteAll(out))
	return buf.Bytes()
}

// facts lists (billing account, sub account, billed) of a Tenant's current facts.
func facts(t *testing.T, w world, tenant string) [][3]string {
	t.Helper()
	var out [][3]string
	must(t, w.s.InTenant(context.Background(), tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(context.Background(), `SELECT billing_account_id, sub_account_id, billed_cost::text FROM cost_facts WHERE current ORDER BY 1, 2, 3`)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) ([3]string, error) {
			var f [3]string
			return f, r.Scan(&f[0], &f[1], &f[2])
		})
		return err
	}))
	return out
}

func openFinding(t *testing.T, w world, tenant, fingerprint string) string {
	t.Helper()
	var title string
	must(t, w.s.InTenant(context.Background(), tenant, func(tx pgx.Tx) error {
		err := tx.QueryRow(context.Background(), `SELECT title FROM findings WHERE fingerprint = $1 AND status = 'open'`, fingerprint).Scan(&title)
		if err == pgx.ErrNoRows {
			return nil
		}
		return err
	}))
	return title
}

// TestClientPayerLoadsLandOnlyInTheirTenant: each client payer's lines land
// in its own Tenant and nowhere else, even when its bill names another
// Tenant's account or tags a line into another Tenant; our payer's sync never
// attributes a client-owned account.
func TestClientPayerLoadsLandOnlyInTheirTenant(t *testing.T) {
	w := setup(t)
	ctx := context.Background()
	c1 := addClient(t, w, "tencent", "c1", "300000000001", "300000000011", "c1-bills-1250000001")
	c2 := addClient(t, w, "tencent", "c2", "300000000002", "300000000022", "c2-bills-1250000002")
	now := time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC)

	buckets := map[string]*memObjects{
		c1.payer: {objs: map[string][]byte{"focus/2026-09-01.csv": bill(t, c1.payer,
			billRow{sub: c1.member, cost: "10.00"},
			billRow{sub: c1.payer, cost: "1.00"},
			billRow{sub: c1.payer, cost: "2.00", tags: `{"keel-scope": "c2/c2-shop/prod"}`}, // tag aims at c2
			billRow{sub: c2.member, cost: "50.00"},                                          // c2's account in c1's bill
			billRow{sub: "200046202634", cost: "60.00"},                                     // our platform account
			billRow{sub: "399999999999", cost: "7.00"},                                      // not registered anywhere
		)}},
		c2.payer: {objs: map[string][]byte{"focus/2026-09-01.csv": bill(t, c2.payer,
			billRow{sub: c2.member, cost: "20.00"},
		)}},
	}
	var connected []string
	cs := &cost.ClientBillSync{Ingester: &cost.Ingester{Store: w.s}, Provider: "tencent", OwnPayers: []string{"200045645249"},
		Now: func() time.Time { return now },
		Connect: func(p cost.ClientPayer) (cost.Objects, cost.InvoiceSource, error) {
			connected = append(connected, p.PayerID+"@"+p.RoleARN)
			return buckets[p.PayerID], fakeInvoices{total: map[string]string{c1.payer: "130.00", c2.payer: "20.00"}[p.PayerID]}, nil
		}}
	runs, err := cs.Run(ctx)
	must(t, err)
	if want := []string{c1.payer + "@qcs::cam::uin/" + c1.payer + ":roleName/KeelReadOnly", c2.payer + "@qcs::cam::uin/" + c2.payer + ":roleName/KeelReadOnly"}; !slices.Equal(connected, want) {
		t.Fatalf("connected %v, want each payer through its own role %v", connected, want)
	}
	if len(runs) != 2 || len(runs[0].Report.Loads) != 1 || len(runs[1].Report.Loads) != 1 {
		t.Fatalf("runs %+v", runs)
	}
	if l := runs[0].Report.Loads[0]; l.Dropped != 3 || l.Reconcile != "ok" {
		t.Errorf("c1 load dropped %d reconcile %q, want 3 dropped and ok against the whole-payer invoice", l.Dropped, l.Reconcile)
	}

	// Our payer's bill names c1's client-owned member account too.
	ours := &memObjects{objs: map[string][]byte{"bills/2026-09-01.csv": bill(t, "200045645249",
		billRow{sub: "200046202634", cost: "5.00"},
		billRow{sub: c1.member, cost: "9.00"},
	)}}
	_, err = (&cost.BillSync{Ingester: &cost.Ingester{Store: w.s}, Objects: ours, Provider: "tencent", BillingAccountID: "200045645249",
		Prefix: "bills/", Mode: cost.PerDayFiles, Now: func() time.Time { return now }}).Run(ctx)
	must(t, err)

	if got, want := facts(t, w, c1.id), [][3]string{{c1.payer, c1.payer, "1.00"}, {c1.payer, c1.payer, "2.00"}, {c1.payer, c1.member, "10.00"}}; !slices.Equal(got, want) {
		t.Errorf("c1 facts %v, want only its own payer's lines for its own accounts %v", got, want)
	}
	if got, want := facts(t, w, c2.id), [][3]string{{c2.payer, c2.member, "20.00"}}; !slices.Equal(got, want) {
		t.Errorf("c2 facts %v, want only its own payer's line %v", got, want)
	}
	if got, want := facts(t, w, w.tat), [][3]string{{"200045645249", "200046202634", "5.00"}}; !slices.Equal(got, want) {
		t.Errorf("tat facts %v, want only our payer's line %v", got, want)
	}
	if got, want := facts(t, w, w.home), [][3]string{{"200045645249", c1.member, "9.00"}}; !slices.Equal(got, want) {
		t.Errorf("home facts %v, want c1's account left unallocated on our payer %v", got, want)
	}
	var dropped int
	var droppedBilled string
	must(t, w.s.InTenant(ctx, w.home, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT dropped_lines, dropped_billed::text FROM cost_loads WHERE billing_account_id = $1 AND superseded_at IS NULL`, c1.payer).Scan(&dropped, &droppedBilled)
	}))
	if dropped != 3 || droppedBilled != "117.000000" {
		t.Errorf("c1 load dropped %d lines worth %s, want 3 worth 117.000000", dropped, droppedBilled)
	}
}

// TestClientPayerWithoutDeliveryRaisesFinding: Keel never sets up delivery;
// it tells the client what to configure and clears the Finding once bills
// arrive.
func TestClientPayerWithoutDeliveryRaisesFinding(t *testing.T) {
	w := setup(t)
	ctx := context.Background()
	unset := addClient(t, w, "tencent", "c1", "300000000001", "300000000011", "")
	empty := addClient(t, w, "tencent", "c2", "300000000002", "300000000022", "c2-bills-1250000002")
	bucket := &memObjects{objs: map[string][]byte{}}
	cs := &cost.ClientBillSync{Ingester: &cost.Ingester{Store: w.s}, Provider: "tencent",
		Connect: func(p cost.ClientPayer) (cost.Objects, cost.InvoiceSource, error) {
			if p.PayerID != empty.payer {
				t.Errorf("connected to %s, which has no bucket", p.PayerID)
			}
			return bucket, nil, nil
		}}
	runs, err := cs.Run(ctx)
	must(t, err)
	if len(runs) != 2 || !runs[0].NoDelivery || !runs[1].NoDelivery {
		t.Fatalf("runs %+v, want both without delivery", runs)
	}
	for _, c := range []clientTenant{unset, empty} {
		if title := openFinding(t, w, c.id, "bill_delivery_missing:tencent/"+c.payer); title == "" {
			t.Errorf("tenant of payer %s has no bill_delivery_missing Finding", c.payer)
		}
		if other := map[string]string{unset.id: empty.id, empty.id: unset.id}[c.id]; openFinding(t, w, other, "bill_delivery_missing:tencent/"+c.payer) != "" {
			t.Errorf("payer %s's Finding leaked into another Tenant", c.payer)
		}
	}

	bucket.objs["focus/2026-09-01.csv"] = bill(t, empty.payer, billRow{sub: empty.member, cost: "4.00"})
	runs, err = cs.Run(ctx)
	must(t, err)
	if runs[1].NoDelivery || len(runs[1].Report.Loads) != 1 {
		t.Fatalf("after delivery %+v", runs[1])
	}
	if title := openFinding(t, w, empty.id, "bill_delivery_missing:tencent/"+empty.payer); title != "" {
		t.Errorf("Finding still open after bills arrived: %s", title)
	}
}

// TestClientPayerCannotBeOurPayer: a client account registered under Keel's
// payer id is refused rather than sharing our payer's loads.
func TestClientPayerCannotBeOurPayer(t *testing.T) {
	w := setup(t)
	addClient(t, w, "tencent", "c1", "200045645249", "300000000011", "c1-bills-1250000001")
	cs := &cost.ClientBillSync{Ingester: &cost.Ingester{Store: w.s}, Provider: "tencent", OwnPayers: []string{"200045645249"},
		Connect: func(cost.ClientPayer) (cost.Objects, cost.InvoiceSource, error) {
			t.Error("connected to Keel's own payer as a client payer")
			return nil, nil, nil
		}}
	if _, err := cs.Run(context.Background()); err == nil {
		t.Fatal("client payer with our payer id ran")
	}
}

// TestOurPayerNeverAllocatesClientAccounts: a client-owned account on Keel's
// own payer bill stays in the home Tenant unallocated, whatever its tags or
// the home Tenant's rules say.
func TestOurPayerNeverAllocatesClientAccounts(t *testing.T) {
	w := setup(t)
	ctx := context.Background()
	c1 := addClient(t, w, "tencent", "c1", "300000000001", "300000000011", "")
	c2 := addClient(t, w, "tencent", "c2", "300000000002", "300000000022", "")
	_, err := cost.Rules{Store: w.s}.Create(ctx, w.home, cost.Rule{Provider: "tencent", SubAccountID: c1.member, Kind: "weights",
		Shares: []cost.Share{{ProjectID: w.project, EnvironmentID: &w.prdEnv, Weight: "1"}}})
	must(t, err)
	ours := &memObjects{objs: map[string][]byte{"bills/2026-09-01.csv": bill(t, "200045645249",
		billRow{sub: "200046202634", cost: "5.00"},
		billRow{sub: c1.member, cost: "6.00"},                                           // home rule aims at tat
		billRow{sub: c2.payer, cost: "3.00", tags: `{"keel-scope": "c2/c2-shop/prod"}`}, // client tag aims at c2
	)}}
	_, err = (&cost.BillSync{Ingester: &cost.Ingester{Store: w.s}, Objects: ours, Provider: "tencent", BillingAccountID: "200045645249",
		Prefix: "bills/", Mode: cost.PerDayFiles, Now: func() time.Time { return time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC) }}).Run(ctx)
	must(t, err)

	if got := facts(t, w, c2.id); len(got) != 0 {
		t.Errorf("c2 facts %v, want none from our payer", got)
	}
	if got, want := facts(t, w, w.tat), [][3]string{{"200045645249", "200046202634", "5.00"}}; !slices.Equal(got, want) {
		t.Errorf("tat facts %v, want only its own account %v", got, want)
	}
	if got, want := facts(t, w, w.home), [][3]string{{"200045645249", c2.payer, "3.00"}, {"200045645249", c1.member, "6.00"}}; !slices.Equal(got, want) {
		t.Errorf("home facts %v, want both client accounts' lines %v", got, want)
	}
	if got := sum(t, w, w.home, `allocation_method <> 'unallocated'`); got != "0" {
		t.Errorf("home holds %s allocated from client accounts, want all unallocated", got)
	}
}

// TestClientPayerAssumeFailureRaisesFinding: when Keel cannot assume a
// client's read-only role, the client's Tenant gets a Finding naming the role
// and the ExternalId its trust policy must require; the next success
// resolves it.
func TestClientPayerAssumeFailureRaisesFinding(t *testing.T) {
	w := setup(t)
	ctx := context.Background()
	c1 := addClient(t, w, "tencent", "c1", "300000000001", "300000000011", "c1-bills-1250000001")
	c2 := addClient(t, w, "tencent", "c2", "300000000002", "300000000022", "c2-bills-1250000002")
	broken := true
	externalIDs := map[string]string{}
	cs := &cost.ClientBillSync{Ingester: &cost.Ingester{Store: w.s}, Provider: "tencent",
		Connect: func(p cost.ClientPayer) (cost.Objects, cost.InvoiceSource, error) {
			externalIDs[p.PayerID] = p.RoleExternalID
			if p.PayerID == c1.payer && broken {
				return nil, nil, &cost.RoleError{Err: errors.New("AssumeRole: role trust policy does not allow this principal")}
			}
			return &memObjects{objs: map[string][]byte{"focus/2026-09-01.csv": bill(t, p.PayerID, billRow{sub: p.PayerID, cost: "1.00"})}}, nil, nil
		}}
	if _, err := cs.Run(ctx); err == nil {
		t.Fatal("a failed AssumeRole was not reported")
	}
	if e1, e2 := externalIDs[c1.payer], externalIDs[c2.payer]; len(e1) != 32 || len(e2) != 32 || e1 == e2 {
		t.Errorf("external ids %q %q, want a distinct one per client payer", e1, e2)
	}
	fp := "client_role_unusable:tencent/" + c1.payer
	title := openFinding(t, w, c1.id, fp)
	if title == "" {
		t.Fatal("c1 has no Finding for its unusable role")
	}
	var configure string
	must(t, w.s.InTenant(ctx, c1.id, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT detail->>'configure' FROM findings WHERE fingerprint = $1 AND status = 'open'`, fp).Scan(&configure)
	}))
	if !strings.Contains(configure, "qcs::cam::uin/"+c1.payer+":roleName/KeelReadOnly") || !strings.Contains(configure, externalIDs[c1.payer]) {
		t.Errorf("Finding hint %q does not name the role and its ExternalId", configure)
	}
	if openFinding(t, w, c2.id, fp) != "" || openFinding(t, w, c2.id, "client_role_unusable:tencent/"+c2.payer) != "" {
		t.Error("c2 got a role Finding")
	}

	broken = false
	_, err := cs.Run(ctx)
	must(t, err)
	if title := openFinding(t, w, c1.id, fp); title != "" {
		t.Errorf("Finding still open after the role worked: %s", title)
	}
}

// TestClientPayerBucketErrorIsDeliveryNotRole: a Connect failure after the
// role was assumed raises bill_delivery_missing, not client_role_unusable,
// and clears a role Finding the earlier runs left open.
func TestClientPayerBucketErrorIsDeliveryNotRole(t *testing.T) {
	w := setup(t)
	ctx := context.Background()
	c1 := addClient(t, w, "tencent", "c1", "300000000001", "300000000011", "c1-bills-1250000001")
	mode := "role"
	cs := &cost.ClientBillSync{Ingester: &cost.Ingester{Store: w.s}, Provider: "tencent",
		Connect: func(p cost.ClientPayer) (cost.Objects, cost.InvoiceSource, error) {
			if mode == "role" {
				return nil, nil, &cost.RoleError{Err: errors.New("AssumeRole refused")}
			}
			return nil, nil, errors.New("bucket endpoint is not valid")
		}}
	if _, err := cs.Run(ctx); err == nil {
		t.Fatal("a refused role was not reported")
	}
	roleFP, deliveryFP := "client_role_unusable:tencent/"+c1.payer, "bill_delivery_missing:tencent/"+c1.payer
	if openFinding(t, w, c1.id, roleFP) == "" || openFinding(t, w, c1.id, deliveryFP) != "" {
		t.Fatal("a role failure must raise only client_role_unusable")
	}

	mode = "bucket"
	if _, err := cs.Run(ctx); err == nil {
		t.Fatal("a bucket error was not reported")
	}
	if title := openFinding(t, w, c1.id, roleFP); title != "" {
		t.Errorf("role Finding still open after the role assumed: %s", title)
	}
	if openFinding(t, w, c1.id, deliveryFP) == "" {
		t.Error("a bucket error after AssumeRole raised no bill_delivery_missing Finding")
	}
}

func lastAssumed(t *testing.T, w world, c clientTenant) *time.Time {
	t.Helper()
	var at *time.Time
	must(t, w.s.InTenant(context.Background(), c.id, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT last_assumed_at FROM client_payers WHERE cloud_account_id = $1`, c.payerAccount).Scan(&at)
	}))
	return at
}

// TestClientPayerRecordsEachSuccessfulAssume: every run that assumes the
// role stamps client_payers.last_assumed_at from the sync's clock, on both
// providers, even when no bill file is new; a refused role and a manual
// resolve of the role Finding leave it alone.
func TestClientPayerRecordsEachSuccessfulAssume(t *testing.T) {
	for _, provider := range []string{"tencent", "aws"} {
		t.Run(provider, func(t *testing.T) {
			w := setup(t)
			ctx := context.Background()
			payer, member, bucket := "300000000001", "300000000011", "c1-bills-1250000001"
			if provider == "aws" {
				payer, member = "111122223333", "444455556666"
			}
			c1 := addClient(t, w, provider, "c1", payer, member, bucket)
			now := time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC)
			broken := true
			cs := &cost.ClientBillSync{Ingester: &cost.Ingester{Store: w.s}, Provider: provider, Now: func() time.Time { return now },
				Connect: func(cost.ClientPayer) (cost.Objects, cost.InvoiceSource, error) {
					if broken {
						return nil, nil, &cost.RoleError{Err: errors.New("AssumeRole refused")}
					}
					return &memObjects{objs: map[string][]byte{}}, nil, nil
				}}
			if _, err := cs.Run(ctx); err == nil {
				t.Fatal("a refused role was not reported")
			}
			if at := lastAssumed(t, w, c1); at != nil {
				t.Fatalf("last_assumed_at = %v after a refused role, want never", at)
			}
			must(t, w.s.InTenant(ctx, c1.id, func(tx pgx.Tx) error {
				_, err := tx.Exec(ctx, `UPDATE findings SET status = 'resolved', resolved_at = $1, resolution = 'duplicate, closing' WHERE status = 'open'`, now.Add(time.Minute))
				return err
			}))
			if at := lastAssumed(t, w, c1); at != nil {
				t.Fatalf("last_assumed_at = %v after a manual resolve, want never", at)
			}

			broken = false
			for _, at := range []time.Time{now.Add(time.Hour), now.Add(2 * time.Hour)} {
				now = at
				_, _ = cs.Run(ctx) // the empty bucket is a delivery error, not a role one
				if got := lastAssumed(t, w, c1); got == nil || !got.Equal(at) {
					t.Errorf("last_assumed_at = %v, want the successful assume at %v", got, at)
				}
			}
		})
	}
}

// TestClientPayerBlockedSyncRaisedInItsTenant: a client payer's period whose
// files overlap is blocked by a Finding in the client's Tenant, where its
// role health reads it, not in Keel's home Tenant, and its hint names the
// client payer's mode and route; the next load resolves it.
func TestClientPayerBlockedSyncRaisedInItsTenant(t *testing.T) {
	w := setup(t)
	ctx := context.Background()
	c1 := addClient(t, w, "tencent", "c1", "300000000001", "300000000011", "c1-bills-1250000001")
	bucket := &memObjects{objs: map[string][]byte{
		"focus/2026-09-01.csv":   bill(t, c1.payer, billRow{sub: c1.member, cost: "1.00"}),
		"focus/2026-09-01-b.csv": bill(t, c1.payer, billRow{sub: c1.member, cost: "1.00"}),
	}}
	cs := &cost.ClientBillSync{Ingester: &cost.Ingester{Store: w.s}, Provider: "tencent",
		Now: func() time.Time { return time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC) },
		Connect: func(cost.ClientPayer) (cost.Objects, cost.InvoiceSource, error) {
			return bucket, nil, nil
		}}
	runs, err := cs.Run(ctx)
	if err == nil || len(runs) != 1 || !slices.Equal(runs[0].Report.Blocked, []string{"2026-09"}) {
		t.Fatalf("runs %+v err %v, want 2026-09 blocked", runs, err)
	}
	fp := "bill_sync_blocked:tencent/" + c1.payer + "/2026-09"
	title := openFinding(t, w, c1.id, fp)
	if title == "" {
		t.Error("the client's Tenant has no bill_sync_blocked Finding for its payer")
	}
	// The client fixes its own payer's mode; Keel's env var is not theirs.
	for _, hint := range []string{title, err.Error()} {
		if !strings.Contains(hint, "client_payers.mode") || !strings.Contains(hint, "PUT /v1/tenants/{tenant}/cloud-accounts/{account}/client-payer") ||
			strings.Contains(hint, "KEEL_TENCENT_BILL_MODE") {
			t.Errorf("client payer blocked hint %q, want client_payers.mode and the client-payer PUT, not KEEL_TENCENT_BILL_MODE", hint)
		}
	}
	if title := openFinding(t, w, w.home, fp); title != "" {
		t.Errorf("the client payer's blocked Finding landed in the home Tenant: %s", title)
	}

	delete(bucket.objs, "focus/2026-09-01-b.csv")
	bucket.objs["focus/2026-09-01-c.csv"] = bill(t, c1.payer, billRow{sub: c1.payer, cost: "2.00"})
	_, err = cs.Run(ctx)
	must(t, err)
	if title := openFinding(t, w, c1.id, fp); title != "" {
		t.Errorf("blocked Finding still open after the period loaded: %s", title)
	}
}
