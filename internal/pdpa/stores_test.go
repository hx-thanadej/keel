package pdpa_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/hx-thanadej/keel/internal/pdpa"
)

func TestPlatformStoresListsEveryConfiguredStoreWithItsRegion(t *testing.T) {
	env := map[string]string{
		"KEEL_ARCHIVE_BUCKET":             "keel-activity-archive",
		"KEEL_ARCHIVE_REGION":             "ap-southeast-7",
		"KEEL_TENCENT_BILL_BUCKET":        "bills-1250000000",
		"KEEL_AWS_BILL_BUCKET":            "keel-cur",
		"KEEL_AWS_REGION":                 "ap-southeast-7",
		"KEEL_ALIBABA_BILL_BUCKET":        "keel-ali-bills",
		"KEEL_GCP_BILL_BUCKET":            "keel-gcp-bills",
		"KEEL_GCP_BILL_BUCKET_REGION":     "asia-southeast1",
		"KEEL_AZURE_BILL_CONTAINER":       "focus",
		"KEEL_AZURE_BILL_STORAGE_ACCOUNT": "keelbills",
		"KEEL_AZURE_BILL_EXPORT_REGION":   "southeastasia",
		"KEEL_DB_REGION":                  "ap-bangkok",
	}
	got, err := pdpa.PlatformStores(func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	want := []pdpa.Location{
		{Kind: "archive", Name: "keel-activity-archive", Region: "ap-southeast-7"},
		{Kind: "bill_bucket", Name: "bills-1250000000", Region: "ap-bangkok"},
		{Kind: "bill_bucket", Name: "keel-cur", Region: "ap-southeast-7"},
		{Kind: "bill_bucket", Name: "keel-ali-bills", Region: "ap-southeast-1"},
		{Kind: "bill_bucket", Name: "keel-gcp-bills", Region: "asia-southeast1"},
		{Kind: "bill_bucket", Name: "keelbills/focus", Region: "southeastasia"},
		{Kind: "database", Name: "keel-postgres", Region: "ap-bangkok"},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("stores\n got %+v\nwant %+v", got, want)
	}
}

func TestPlatformStoresAlwaysListsKeelsDatabaseEvenWithoutARegion(t *testing.T) {
	got, err := pdpa.PlatformStores(func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	if want := []pdpa.Location{{Kind: "database", Name: "keel-postgres"}}; !slices.Equal(got, want) {
		t.Fatalf("stores %+v, want only the database with no region (checked as unknown)", got)
	}
}

func TestPlatformStoresRefusesAConfiguredStoreWithNoRegion(t *testing.T) {
	for missing, env := range map[string]map[string]string{
		"KEEL_GCP_BILL_BUCKET_REGION":   {"KEEL_GCP_BILL_BUCKET": "keel-gcp-bills"},
		"KEEL_AZURE_BILL_EXPORT_REGION": {"KEEL_AZURE_BILL_CONTAINER": "focus", "KEEL_AZURE_BILL_STORAGE_ACCOUNT": "keelbills"},
		"KEEL_ARCHIVE_REGION":           {"KEEL_ARCHIVE_BUCKET": "keel-activity-archive"},
	} {
		_, err := pdpa.PlatformStores(func(k string) string { return env[k] })
		if err == nil || !strings.Contains(err.Error(), missing) {
			t.Errorf("%v: err %v, want it to name %s", env, err, missing)
		}
	}
}
