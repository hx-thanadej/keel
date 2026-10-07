package utilisation

import (
	"context"
	"fmt"
	"time"

	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	monitor "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/monitor/v20180724"
)

// MonitorAPI is the slice of Tencent Cloud Monitor the collector uses.
type MonitorAPI interface {
	GetMonitorDataWithContext(ctx context.Context, req *monitor.GetMonitorDataRequest) (*monitor.GetMonitorDataResponse, error)
}

// NewMonitorClient builds a Cloud Monitor client for one account's credentials.
func NewMonitorClient(region string, creds common.Provider) (MonitorAPI, error) {
	cred, err := creds.GetCredential()
	if err != nil {
		return nil, fmt.Errorf("tencent credentials: %w", err)
	}
	return monitor.NewClient(cred, region, profile.NewClientProfile())
}

// TencentCVM collects CVM CPU and memory utilisation (percent) from Cloud
// Monitor at period=60. Period 3600 returns each hour's MAX rather than an
// average, which would inflate every percentile, so it is never used.
type TencentCVM struct {
	API MonitorAPI
}

// perCall keeps one request under Cloud Monitor's 7200-point limit:
// 1440 one-minute points per instance per day × 5 = 7200.
const perCall = 5

// Day summarises each instance's CPUUsage and MemUsage for the UTC day.
// MemUsage needs the CVM monitoring agent; instances without it get CPU only.
func (c TencentCVM) Day(ctx context.Context, instances []string, day time.Time) ([]Summary, error) {
	var out []Summary
	for _, metric := range []struct{ name, ours string }{{"CPUUsage", "cpu_pct"}, {"MemUsage", "memory_pct"}} {
		for i := 0; i < len(instances); i += perCall {
			batch := instances[i:min(i+perCall, len(instances))]
			req := monitor.NewGetMonitorDataRequest()
			ns, period := "QCE/CVM", uint64(60)
			start, end := day.UTC().Format(time.RFC3339), day.UTC().Add(24*time.Hour-time.Minute).Format(time.RFC3339)
			req.Namespace, req.MetricName, req.Period, req.StartTime, req.EndTime = &ns, &metric.name, &period, &start, &end
			for _, id := range batch {
				name, value := "InstanceId", id
				req.Instances = append(req.Instances, &monitor.Instance{Dimensions: []*monitor.Dimension{{Name: &name, Value: &value}}})
			}
			res, err := c.API.GetMonitorDataWithContext(ctx, req)
			if err != nil {
				return nil, fmt.Errorf("GetMonitorData %s: %w", metric.name, err)
			}
			if res.Response == nil {
				continue
			}
			for _, dp := range res.Response.DataPoints {
				if dp == nil {
					continue
				}
				id := ""
				for _, d := range dp.Dimensions {
					if d != nil && d.Name != nil && *d.Name == "InstanceId" && d.Value != nil {
						id = *d.Value
					}
				}
				var xs, ts []float64
				for i, v := range dp.Values {
					if v == nil {
						continue
					}
					at := float64(day.UTC().Unix() + int64(i)*60) // positional if Timestamps is absent
					if i < len(dp.Timestamps) && dp.Timestamps[i] != nil {
						at = *dp.Timestamps[i]
					}
					xs, ts = append(xs, *v), append(ts, at)
				}
				if id == "" || len(xs) == 0 {
					continue
				}
				s := Summarize(xs)
				s.Provider, s.ResourceType, s.ResourceID, s.Metric, s.Day = "tencent", "vm", id, metric.ours, day
				s.Hourly = HourlyMax(day, ts, xs)
				out = append(out, s)
			}
		}
	}
	return out, nil
}
