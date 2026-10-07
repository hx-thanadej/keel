package tencent_test

import (
	"encoding/json"
	"testing"

	cvm "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/cvm/v20170312"

	"github.com/hx-thanadej/keel/internal/cloud/tencent"
)

func TestCatalogFromQuota(t *testing.T) {
	// Shape of DescribeZoneInstanceConfigInfos; same type in two zones, one sold out type.
	raw := `{"InstanceTypeQuotaSet": [
		{"Zone": "ap-bangkok-1", "InstanceType": "S5.LARGE8", "InstanceFamily": "S5", "Cpu": 4, "Memory": 8, "Status": "SELL", "Price": {"UnitPrice": 0.12, "ChargeUnit": "HOUR"}},
		{"Zone": "ap-bangkok-2", "InstanceType": "S5.LARGE8", "InstanceFamily": "S5", "Cpu": 4, "Memory": 8, "Status": "SELL", "Price": {"UnitPrice": 0.11, "ChargeUnit": "HOUR"}},
		{"Zone": "ap-bangkok-1", "InstanceType": "S5.MEDIUM4", "InstanceFamily": "S5", "Cpu": 2, "Memory": 4, "Status": "SOLD_OUT", "Price": {"UnitPrice": 0.06}}]}`
	var r cvm.DescribeZoneInstanceConfigInfosResponseParams
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		t.Fatal(err)
	}
	types := tencent.CatalogFromQuota(&r)
	if len(types) != 1 || types[0].Name != "S5.LARGE8" || types[0].HourlyPrice != 0.11 || types[0].CPU != 4 || types[0].MemoryGiB != 8 || types[0].Family != "S5" {
		t.Fatalf("types %+v", types)
	}
}
