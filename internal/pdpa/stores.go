package pdpa

import "fmt"

// DatabaseName names Keel's own Postgres as a residency Location.
const DatabaseName = "keel-postgres"

// PlatformStores reads, through getenv, the platform stores that hold every
// Tenant's data or logs (#190, #206): the Activity Log archive, each
// configured bill bucket or export, and Keel's Postgres. It performs no I/O.
// A configured bucket whose region is unknown is an error naming the missing
// variable, so no store is silently left out. Keel's database is always
// listed; with KEEL_DB_REGION unset its Region is empty and each residency
// run reports it as not checked.
func PlatformStores(getenv func(string) string) ([]Location, error) {
	or := func(key, def string) string {
		if v := getenv(key); v != "" {
			return v
		}
		return def
	}
	var out []Location
	add := func(kind, name, nameVar, region, regionVar string) error {
		if name == "" {
			return nil
		}
		if region == "" {
			return fmt.Errorf("%s is required with %s: the PDPA residency check needs the store's region", regionVar, nameVar)
		}
		out = append(out, Location{Kind: kind, Name: name, Region: region})
		return nil
	}
	azure := ""
	if c := getenv("KEEL_AZURE_BILL_CONTAINER"); c != "" {
		azure = getenv("KEEL_AZURE_BILL_STORAGE_ACCOUNT") + "/" + c
	}
	for _, err := range []error{
		add("archive", getenv("KEEL_ARCHIVE_BUCKET"), "KEEL_ARCHIVE_BUCKET", getenv("KEEL_ARCHIVE_REGION"), "KEEL_ARCHIVE_REGION"),
		add("bill_bucket", getenv("KEEL_TENCENT_BILL_BUCKET"), "KEEL_TENCENT_BILL_BUCKET", or("KEEL_TENCENT_REGION", "ap-bangkok"), "KEEL_TENCENT_REGION"),
		add("bill_bucket", getenv("KEEL_AWS_BILL_BUCKET"), "KEEL_AWS_BILL_BUCKET", or("KEEL_AWS_REGION", "us-east-1"), "KEEL_AWS_REGION"),
		add("bill_bucket", getenv("KEEL_ALIBABA_BILL_BUCKET"), "KEEL_ALIBABA_BILL_BUCKET", or("KEEL_ALIBABA_REGION", "ap-southeast-1"), "KEEL_ALIBABA_REGION"),
		add("bill_bucket", getenv("KEEL_GCP_BILL_BUCKET"), "KEEL_GCP_BILL_BUCKET", getenv("KEEL_GCP_BILL_BUCKET_REGION"), "KEEL_GCP_BILL_BUCKET_REGION"),
		add("bill_bucket", azure, "KEEL_AZURE_BILL_CONTAINER", getenv("KEEL_AZURE_BILL_EXPORT_REGION"), "KEEL_AZURE_BILL_EXPORT_REGION"),
	} {
		if err != nil {
			return nil, err
		}
	}
	return append(out, Location{Kind: "database", Name: DatabaseName, Region: getenv("KEEL_DB_REGION")}), nil
}
