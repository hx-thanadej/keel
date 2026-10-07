package utilisation_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	monitor "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/monitor/v20180724"

	"github.com/hx-thanadej/keel/internal/utilisation"
)

type fakeMonitor struct {
	calls []*monitor.GetMonitorDataRequest
}

func (f *fakeMonitor) GetMonitorDataWithContext(_ context.Context, req *monitor.GetMonitorDataRequest) (*monitor.GetMonitorDataResponse, error) {
	f.calls = append(f.calls, req)
	var dps []map[string]any
	for _, inst := range req.Instances {
		id := *inst.Dimensions[0].Value
		if *req.MetricName == "MemUsage" && id == "ins-noagent" {
			continue // no monitoring agent → no memory data
		}
		var vals []float64
		for i := 0; i < 1440; i++ {
			vals = append(vals, float64(10+i%20)) // 10..29 %
		}
		dps = append(dps, map[string]any{"Dimensions": []map[string]string{{"Name": "InstanceId", "Value": id}}, "Values": vals})
	}
	raw, _ := json.Marshal(map[string]any{"Response": map[string]any{"MetricName": *req.MetricName, "Period": 60, "DataPoints": dps}})
	var res monitor.GetMonitorDataResponse
	return &res, json.Unmarshal(raw, &res)
}

func TestTencentCVMCollector(t *testing.T) {
	f := &fakeMonitor{}
	var ids []string
	for i := 0; i < 11; i++ {
		ids = append(ids, fmt.Sprintf("ins-%02d", i))
	}
	ids = append(ids, "ins-noagent")
	sums, err := utilisation.TencentCVM{API: f}.Day(context.Background(), ids, day)
	if err != nil {
		t.Fatal(err)
	}
	// 12 instances → 3 calls per metric (5+5+2), always period 60.
	if len(f.calls) != 6 {
		t.Fatalf("calls %d, want 6", len(f.calls))
	}
	for _, c := range f.calls {
		if *c.Period != 60 || len(c.Instances) > 5 || *c.Namespace != "QCE/CVM" {
			t.Fatalf("bad request %+v", c)
		}
	}
	if len(sums) != 23 { // 12 cpu + 11 memory
		t.Fatalf("summaries %d", len(sums))
	}
	for _, s := range sums {
		if s.Max != 29 || s.Samples != 1440 || s.ResourceType != "vm" {
			t.Fatalf("summary %+v", s)
		}
	}
}
