package cost_test

import (
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/cost"
)

// awsExport writes an AWS Data Exports FOCUS 1.2 file for management
// account payer, every column taken from the fixture's first line except
// the account, costs and tags.
func awsExport(t *testing.T, payer string, rows ...billRow) []byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/aws-focus-2026-09.csv")
	must(t, err)
	in, err := csv.NewReader(bytes.NewReader(raw)).ReadAll()
	must(t, err)
	col := map[string]int{}
	for i, h := range in[0] {
		col[h] = i
	}
	out := [][]string{in[0]}
	for _, r := range rows {
		line := slices.Clone(in[1])
		tags := r.tags
		if tags == "" {
			tags = "{}"
		}
		for name, v := range map[string]string{"BillingAccountId": payer, "SubAccountId": r.sub, "BilledCost": r.cost, "EffectiveCost": r.cost, "ListCost": r.cost, "ContractedCost": r.cost, "Tags": tags} {
			line[col[name]] = v
		}
		out = append(out, line)
	}
	var buf bytes.Buffer
	must(t, csv.NewWriter(&buf).WriteAll(out))
	return buf.Bytes()
}

// exportBucket holds one Data Exports run under focus/, split into parts.
func exportBucket(parts ...[]byte) *etagObjects {
	b := &etagObjects{memObjects: memObjects{objs: map[string][]byte{}}, etags: map[string]string{}}
	for i, p := range parts {
		key := "focus/data/BILLING_PERIOD=2026-09/part-" + string(rune('0'+i)) + ".csv"
		b.objs[key], b.etags[key] = p, "v1"
	}
	return b
}

// TestAWSClientPayersLandOnlyInTheirTenant: two client management accounts
// and Keel's own. Each client's export lands in its own Tenant through its
// own role; a line naming another Tenant's account, Keel's account, an
// unregistered account, or tagged into another Tenant never leaves it;
// Keel's export never attributes a client-owned account.
func TestAWSClientPayersLandOnlyInTheirTenant(t *testing.T) {
	w := awsWorld(t)
	ctx := context.Background()
	c1 := addClient(t, w, "aws", "c1", "300000000001", "300000000011", "c1-bills")
	c2 := addClient(t, w, "aws", "c2", "300000000002", "300000000022", "c2-bills")
	now := time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC)

	buckets := map[string]*etagObjects{
		c1.payer: exportBucket(
			awsExport(t, c1.payer,
				billRow{sub: c1.member, cost: "10.00"},
				billRow{sub: c1.payer, cost: "1.00"},
				billRow{sub: c1.payer, cost: "2.00", tags: `{"keel-scope": "c2/c2-shop/prod"}`}, // tag aims at c2
			),
			awsExport(t, c1.payer,
				billRow{sub: c2.member, cost: "50.00"},      // c2's account in c1's export
				billRow{sub: "222222222222", cost: "60.00"}, // Keel's platform account
				billRow{sub: "399999999999", cost: "7.00"},  // registered nowhere
			),
		),
		c2.payer: exportBucket(awsExport(t, c2.payer, billRow{sub: c2.member, cost: "20.00"})),
	}
	sibling := "focus2/data/BILLING_PERIOD=2026-09/part-0.csv.gz"
	buckets[c1.payer].objs[sibling], buckets[c1.payer].etags[sibling] = awsExport(t, c1.payer, billRow{sub: c1.member, cost: "99.00"}), "v1"
	var connected []string
	var prefixes []string
	cs := &cost.ClientBillSync{Ingester: &cost.Ingester{Store: w.s}, Provider: "aws", OwnPayers: []string{"111111111111"},
		Now: func() time.Time { return now },
		Connect: func(p cost.ClientPayer) (cost.Objects, cost.InvoiceSource, error) {
			connected = append(connected, p.PayerID+"@"+p.RoleARN+"@"+p.Bucket+"@"+p.Region)
			prefixes = append(prefixes, p.Prefix)
			return buckets[p.PayerID], nil, nil
		}}
	runs, err := cs.Run(ctx)
	must(t, err)
	if want := []string{c1.payer + "@arn:aws:iam::" + c1.payer + ":role/KeelReadOnly@c1-bills@us-east-1", c2.payer + "@arn:aws:iam::" + c2.payer + ":role/KeelReadOnly@c2-bills@us-east-1"}; !slices.Equal(connected, want) {
		t.Fatalf("connected %v, want each management account through its own role %v", connected, want)
	}
	if want := []string{"focus/", "focus/"}; !slices.Equal(prefixes, want) {
		t.Fatalf("connected with prefixes %q, want the stored folder prefix %q given a trailing slash", prefixes, want)
	}
	if len(runs) != 2 || len(runs[0].Report.Loads) != 1 || runs[0].Report.Loads[0].Dropped != 3 || len(runs[1].Report.Loads) != 1 {
		t.Fatalf("runs %+v, want one load each and c1's three foreign lines dropped", runs)
	}

	ours := exportBucket(awsExport(t, "111111111111",
		billRow{sub: "222222222222", cost: "5.00"},
		billRow{sub: c1.member, cost: "9.00", tags: `{"keel-scope": "c1/c1-shop/prod"}`},
	))
	_, err = (&cost.BillSync{Ingester: &cost.Ingester{Store: w.s}, Objects: ours, Provider: "aws", BillingAccountID: "111111111111",
		Prefix: "focus/", Mode: cost.LatestExportFolder, Now: func() time.Time { return now }}).Run(ctx)
	must(t, err)

	if got, want := facts(t, w, c1.id), [][3]string{{c1.payer, c1.payer, "1.00"}, {c1.payer, c1.payer, "2.00"}, {c1.payer, c1.member, "10.00"}}; !slices.Equal(got, want) {
		t.Errorf("c1 facts %v, want only its own export's lines for its own accounts %v", got, want)
	}
	if got, want := facts(t, w, c2.id), [][3]string{{c2.payer, c2.member, "20.00"}}; !slices.Equal(got, want) {
		t.Errorf("c2 facts %v, want only its own export's line %v", got, want)
	}
	if got, want := facts(t, w, w.tat), [][3]string{{"111111111111", "222222222222", "5.00"}}; !slices.Equal(got, want) {
		t.Errorf("tat facts %v, want only Keel's export's line %v", got, want)
	}
	if got, want := facts(t, w, w.home), [][3]string{{"111111111111", c1.member, "9.00"}}; !slices.Equal(got, want) {
		t.Errorf("home facts %v, want c1's account left unallocated on Keel's export %v", got, want)
	}
	var dropped int
	var droppedBilled string
	must(t, w.s.InTenant(ctx, w.home, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT dropped_lines, dropped_billed::text FROM cost_loads WHERE provider = 'aws' AND billing_account_id = $1 AND superseded_at IS NULL`, c1.payer).Scan(&dropped, &droppedBilled)
	}))
	if dropped != 3 || droppedBilled != "117.000000" {
		t.Errorf("c1 load dropped %d lines worth %s, want 3 worth 117.000000", dropped, droppedBilled)
	}
}

// TestAWSClientPayerFindingsSayWhatToConfigureInAWS: a role Keel cannot
// assume and a management account without an export each raise a Finding
// in that client's Tenant only, worded for AWS, and clear once fixed.
func TestAWSClientPayerFindingsSayWhatToConfigureInAWS(t *testing.T) {
	w := awsWorld(t)
	ctx := context.Background()
	c1 := addClient(t, w, "aws", "c1", "300000000001", "300000000011", "c1-bills")
	c2 := addClient(t, w, "aws", "c2", "300000000002", "300000000022", "")
	broken := true
	var externalID string
	cs := &cost.ClientBillSync{Ingester: &cost.Ingester{Store: w.s}, Provider: "aws",
		Connect: func(p cost.ClientPayer) (cost.Objects, cost.InvoiceSource, error) {
			if p.PayerID != c1.payer {
				t.Errorf("connected to %s, which has no bucket", p.PayerID)
			}
			externalID = p.RoleExternalID
			if broken {
				return nil, nil, &cost.RoleError{Err: errors.New("AccessDenied: not authorized to perform sts:AssumeRole")}
			}
			return exportBucket(awsExport(t, p.PayerID, billRow{sub: c1.member, cost: "4.00"})), nil, nil
		}}
	if _, err := cs.Run(ctx); err == nil {
		t.Fatal("a refused AssumeRole was not reported")
	}
	configure := func(tenant, fp string) string {
		var s string
		must(t, w.s.InTenant(ctx, tenant, func(tx pgx.Tx) error {
			err := tx.QueryRow(ctx, `SELECT detail->>'configure' FROM findings WHERE fingerprint = $1 AND status = 'open'`, fp).Scan(&s)
			if err == pgx.ErrNoRows {
				return nil
			}
			return err
		}))
		return s
	}
	roleFP, deliveryFP := "client_role_unusable:aws/"+c1.payer, "bill_delivery_missing:aws/"+c2.payer
	for _, want := range []string{"arn:aws:iam::" + c1.payer + ":role/KeelReadOnly", "StringEquals sts:ExternalId " + externalID} {
		if got := configure(c1.id, roleFP); !strings.Contains(got, want) {
			t.Errorf("c1 role Finding says %q, want it to name %q", got, want)
		}
	}
	for _, want := range []string{"Data Exports", "FOCUS 1.2", "s3:ListBucket", "s3:GetObject", "arn:aws:iam::" + c2.payer + ":role/KeelReadOnly"} {
		if got := configure(c2.id, deliveryFP); !strings.Contains(got, want) {
			t.Errorf("c2 delivery Finding says %q, want it to name %q", got, want)
		}
	}
	if configure(c2.id, roleFP) != "" || configure(c1.id, deliveryFP) != "" {
		t.Error("a client's Finding leaked into the other client's Tenant")
	}

	broken = false
	_, err := cs.Run(ctx)
	must(t, err)
	if got := openFinding(t, w, c1.id, roleFP); got != "" {
		t.Errorf("role Finding still open after the role worked: %s", got)
	}
	if got := facts(t, w, c1.id); len(got) != 1 {
		t.Errorf("c1 facts %v after the role worked, want its export loaded", got)
	}
}

// TestKeelIdentityFailureRaisesNoClientFinding: when Keel's own identity is
// unusable (static keys instead of web identity), the run fails once with
// that error and raises keel_identity_unusable in Keel's home Tenant. No
// client is told to fix its trust policy, and no role is tried. With no
// payers the identity is not checked at all.
func TestKeelIdentityFailureRaisesNoClientFinding(t *testing.T) {
	w := awsWorld(t)
	ctx := context.Background()
	checked := 0
	ready := func(context.Context) error {
		checked++
		return errors.New(`aws credentials from "EnvConfigCredentials" refused: never access keys`)
	}
	cs := &cost.ClientBillSync{Ingester: &cost.Ingester{Store: w.s}, Provider: "aws", Ready: ready,
		Connect: func(p cost.ClientPayer) (cost.Objects, cost.InvoiceSource, error) {
			t.Errorf("connected to %s with Keel's identity refused", p.PayerID)
			return nil, nil, errors.New("unreachable")
		}}
	if _, err := cs.Run(ctx); err != nil || checked != 0 {
		t.Fatalf("run with no payers = %v after %d identity checks, want nil after none", err, checked)
	}
	c1 := addClient(t, w, "aws", "c1", "300000000001", "300000000011", "c1-bills")
	c2 := addClient(t, w, "aws", "c2", "300000000002", "300000000022", "c2-bills")
	runs, err := cs.Run(ctx)
	if err == nil || !strings.Contains(err.Error(), "never access keys") || len(runs) != 0 || checked != 1 {
		t.Fatalf("run = %v, %v after %d identity checks; want one error naming Keel's identity", runs, err, checked)
	}
	for _, c := range []clientTenant{c1, c2} {
		if got := openFinding(t, w, c.id, "client_role_unusable:aws/"+c.payer); got != "" {
			t.Errorf("client %s got a role Finding for Keel's own fault: %s", c.payer, got)
		}
	}
	if openFinding(t, w, w.home, "keel_identity_unusable:aws") == "" {
		t.Error("Keel's home Tenant has no Finding for its unusable AWS identity")
	}
}
