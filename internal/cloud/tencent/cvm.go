package tencent

import (
	"context"
	"fmt"

	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	cvm "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/cvm/v20170312"

	"github.com/hx-thanadej/keel/internal/rightsize"
)

// CVMAPI is the slice of the CVM API the rightsizing adapters use.
type CVMAPI interface {
	DescribeZoneInstanceConfigInfosWithContext(ctx context.Context, req *cvm.DescribeZoneInstanceConfigInfosRequest) (*cvm.DescribeZoneInstanceConfigInfosResponse, error)
	DescribeInstancesWithContext(ctx context.Context, req *cvm.DescribeInstancesRequest) (*cvm.DescribeInstancesResponse, error)
}

// NewCVM builds a CVM client.
func NewCVM(region string, creds common.Provider) (CVMAPI, error) {
	cred, err := creds.GetCredential()
	if err != nil {
		return nil, err
	}
	return cvm.NewClient(cred, region, profile.NewClientProfile())
}

// Catalog lists on-sale pay-as-you-go instance types with their hourly list
// price (the lowest across zones), for rightsizing price ratios (#70).
type Catalog struct{ API CVMAPI }

// Types implements rightsize.Catalog.
func (c Catalog) Types(ctx context.Context, _ string) ([]rightsize.InstanceType, error) {
	req := cvm.NewDescribeZoneInstanceConfigInfosRequest()
	name, charge := "instance-charge-type", "POSTPAID_BY_HOUR"
	req.Filters = []*cvm.Filter{{Name: &name, Values: []*string{&charge}}}
	res, err := c.API.DescribeZoneInstanceConfigInfosWithContext(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("DescribeZoneInstanceConfigInfos: %w", err)
	}
	return CatalogFromQuota(res.Response), nil
}

// CatalogFromQuota maps the response, keeping types that are on sale.
func CatalogFromQuota(r *cvm.DescribeZoneInstanceConfigInfosResponseParams) []rightsize.InstanceType {
	best := map[string]rightsize.InstanceType{}
	if r == nil {
		return nil
	}
	for _, q := range r.InstanceTypeQuotaSet {
		if q == nil || q.InstanceType == nil || q.Cpu == nil || q.Memory == nil || q.Price == nil || q.Price.UnitPrice == nil {
			continue
		}
		if q.Status != nil && *q.Status != "SELL" {
			continue
		}
		t := rightsize.InstanceType{Name: *q.InstanceType, CPU: float64(*q.Cpu), MemoryGiB: float64(*q.Memory), HourlyPrice: *q.Price.UnitPrice}
		if q.InstanceFamily != nil {
			t.Family = *q.InstanceFamily
		}
		if cur, ok := best[t.Name]; !ok || t.HourlyPrice < cur.HourlyPrice {
			best[t.Name] = t
		}
	}
	out := make([]rightsize.InstanceType, 0, len(best))
	for _, t := range best {
		out = append(out, t)
	}
	return out
}

// Inventory reads current instance types in one account.
type Inventory struct{ API CVMAPI }

// InstanceTypes implements rightsize.Inventory (100 ids per call).
func (i Inventory) InstanceTypes(ctx context.Context, _ string, ids []string) (map[string]string, error) {
	out := map[string]string{}
	for start := 0; start < len(ids); start += 100 {
		req := cvm.NewDescribeInstancesRequest()
		req.InstanceIds = common.StringPtrs(ids[start:min(start+100, len(ids))])
		limit := int64(100)
		req.Limit = &limit
		res, err := i.API.DescribeInstancesWithContext(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("DescribeInstances: %w", err)
		}
		if res.Response == nil {
			continue
		}
		for _, in := range res.Response.InstanceSet {
			if in != nil && in.InstanceId != nil && in.InstanceType != nil {
				out[*in.InstanceId] = *in.InstanceType
			}
		}
	}
	return out, nil
}
