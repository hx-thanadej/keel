package cost_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/cost"
)

// etagObjects is memObjects that also reports ETags, like S3.
type etagObjects struct {
	memObjects
	etags map[string]string
}

func (e *etagObjects) ListWithETag(ctx context.Context, prefix string) ([]cost.ObjectInfo, error) {
	keys, err := e.List(ctx, prefix)
	var out []cost.ObjectInfo
	for _, k := range keys {
		out = append(out, cost.ObjectInfo{Key: k, ETag: e.etags[k]})
	}
	return out, err
}

func awsWorld(t *testing.T) world {
	w := setup(t)
	must(t, w.s.InTenant(context.Background(), w.tat, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `INSERT INTO cloud_accounts (tenant_id, environment_id, provider, external_id, name) VALUES ($1, $2, 'aws', '222222222222', 'tat-crm-prod-aws')`, w.tat, w.prdEnv)
		return err
	}))
	return w
}

func TestAWSFocusKeepsSourceEffectiveCost(t *testing.T) {
	w := awsWorld(t)
	raw, err := os.ReadFile("testdata/aws-focus-2026-09.csv")
	must(t, err)
	lines, err := cost.ParseFOCUS(raw)
	must(t, err)
	res, err := (&cost.Ingester{Store: w.s}).Load(context.Background(), cost.Load{Provider: "aws", BillingAccountID: "111111111111", BillingPeriod: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC), Lines: lines})
	must(t, err)
	if res.Allocated != 3 || res.Lines != 3 {
		t.Fatalf("result %+v", res)
	}
	var billed, effective, method string
	must(t, w.s.InTenant(context.Background(), w.tat, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT sum(billed_cost)::text, sum(effective_cost)::text, string_agg(DISTINCT effective_cost_method, ',')
			FROM cost_facts WHERE current AND provider = 'aws' AND environment_id = $1`, w.prdEnv).Scan(&billed, &effective, &method)
	}))
	if billed != "21.00" || effective != "14.00" || method != "source" {
		t.Errorf("aws billed %s effective %s method %s", billed, effective, method)
	}
}

func TestAWSOverwrittenExportReloadsAndFinalisesOnInvoice(t *testing.T) {
	w := awsWorld(t)
	mtd, _ := os.ReadFile("testdata/aws-focus-2026-09.csv")
	inv, _ := os.ReadFile("testdata/aws-focus-2026-09-invoiced.csv")
	key := "exports/focus/data/BILLING_PERIOD=2026-09/focus-00001.csv"
	objs := &etagObjects{memObjects: memObjects{objs: map[string][]byte{key: splitAWS(t, mtd, 2)}}, etags: map[string]string{key: "v1"}}
	now := time.Date(2026, 9, 2, 6, 0, 0, 0, time.UTC)
	bs := &cost.BillSync{Ingester: &cost.Ingester{Store: w.s}, Objects: objs, Provider: "aws", BillingAccountID: "111111111111",
		Prefix: "exports/focus/", Mode: cost.LatestExportFolder, Now: func() time.Time { return now }}
	rep, err := bs.Run(context.Background())
	must(t, err)
	if len(rep.Loads) != 1 || rep.Loads[0].Lines != 2 {
		t.Fatalf("first %+v", rep)
	}

	// AWS overwrites the same key with month-to-date data: new ETag → reload.
	objs.objs[key], objs.etags[key] = mtd, "v2"
	rep, err = bs.Run(context.Background())
	must(t, err)
	if rep.NewFiles != 1 || len(rep.Loads) != 1 || rep.Loads[0].Lines != 3 || rep.Loads[0].Final {
		t.Fatalf("overwrite %+v", rep)
	}
	if got := sum(t, w, w.tat, "provider = 'aws'"); got != "21.00" {
		t.Fatalf("aws billed after overwrite %s, want 21.00 (not doubled)", got)
	}

	// Invoiced export after the 15th: final.
	now = time.Date(2026, 10, 16, 0, 0, 0, 0, time.UTC)
	objs.objs[key], objs.etags[key] = inv, "v3"
	rep, err = bs.Run(context.Background())
	must(t, err)
	if len(rep.Loads) != 1 || !rep.Loads[0].Final {
		t.Fatalf("invoiced %+v", rep)
	}
}

// splitAWS keeps the header and the first n data rows.
func splitAWS(t *testing.T, raw []byte, n int) []byte {
	t.Helper()
	lines := []byte{}
	count := -1
	for _, l := range splitLines(raw) {
		if count >= n {
			break
		}
		lines = append(lines, l...)
		count++
	}
	return lines
}

func splitLines(b []byte) [][]byte {
	var out [][]byte
	start := 0
	for i, c := range b {
		if c == '\n' {
			out = append(out, b[start:i+1])
			start = i + 1
		}
	}
	return out
}

func TestLatestExportFolderLoadsAllPartsOfNewestRun(t *testing.T) {
	w := awsWorld(t)
	mtd, _ := os.ReadFile("testdata/aws-focus-2026-09.csv")
	all := splitLines(mtd)
	header := all[0]
	part := func(rows ...[]byte) []byte {
		out := append([]byte{}, header...)
		for _, r := range rows {
			out = append(out, r...)
		}
		return out
	}
	objs := &etagObjects{memObjects: memObjects{objs: map[string][]byte{
		"exp/20260902T0000Z/part-0.csv": part(all[1]),         // older run: day 1 EC2 only
		"exp/20260903T0000Z/part-0.csv": part(all[1], all[2]), // newest run, split in two parts
		"exp/20260903T0000Z/part-1.csv": part(all[3]),
	}}, etags: map[string]string{}}
	bs := &cost.BillSync{Ingester: &cost.Ingester{Store: w.s}, Objects: objs, Provider: "aws", BillingAccountID: "111111111111",
		Prefix: "exp/", Mode: cost.LatestExportFolder, Now: func() time.Time { return time.Date(2026, 9, 3, 6, 0, 0, 0, time.UTC) }}
	rep, err := bs.Run(context.Background())
	must(t, err)
	if len(rep.Loads) != 1 || rep.Loads[0].Lines != 3 {
		t.Fatalf("loads %+v", rep.Loads)
	}
	if got := sum(t, w, w.tat, "provider = 'aws'"); got != "21.00" {
		t.Fatalf("billed %s, want 21.00 from the newest run only", got)
	}
}
