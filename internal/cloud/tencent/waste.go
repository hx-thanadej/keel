package tencent

import (
	"context"
	"errors"
	"fmt"

	cbs "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/cbs/v20170312"
	clb "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/clb/v20180317"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	cvm "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/cvm/v20170312"
	vpc "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/vpc/v20170312"

	"github.com/hx-thanadej/keel/internal/rightsize"
)

// Waste APIs used by the scanner and cleaner (narrow, for fakes in tests).
type (
	DiskAPI interface {
		DescribeDisksWithContext(context.Context, *cbs.DescribeDisksRequest) (*cbs.DescribeDisksResponse, error)
		CreateSnapshotWithContext(context.Context, *cbs.CreateSnapshotRequest) (*cbs.CreateSnapshotResponse, error)
		TerminateDisksWithContext(context.Context, *cbs.TerminateDisksRequest) (*cbs.TerminateDisksResponse, error)
	}
	AddressAPI interface {
		DescribeAddressesWithContext(context.Context, *vpc.DescribeAddressesRequest) (*vpc.DescribeAddressesResponse, error)
		ReleaseAddressesWithContext(context.Context, *vpc.ReleaseAddressesRequest) (*vpc.ReleaseAddressesResponse, error)
	}
	LBAPI interface {
		DescribeLoadBalancersWithContext(context.Context, *clb.DescribeLoadBalancersRequest) (*clb.DescribeLoadBalancersResponse, error)
		DescribeTargetsWithContext(context.Context, *clb.DescribeTargetsRequest) (*clb.DescribeTargetsResponse, error)
	}
)

// Waste scans one account for idle/orphaned resources and cleans them (#72).
type Waste struct {
	Disks     DiskAPI
	Addresses AddressAPI
	LBs       LBAPI
	CVM       CVMAPI
}

// NewWaste builds clients for one account's credentials.
func NewWaste(region string, creds common.Provider) (*Waste, error) {
	cred, err := creds.GetCredential()
	if err != nil {
		return nil, err
	}
	p := profile.NewClientProfile()
	d, err := cbs.NewClient(cred, region, p)
	if err != nil {
		return nil, err
	}
	a, err := vpc.NewClient(cred, region, p)
	if err != nil {
		return nil, err
	}
	l, err := clb.NewClient(cred, region, p)
	if err != nil {
		return nil, err
	}
	c, err := cvm.NewClient(cred, region, p)
	if err != nil {
		return nil, err
	}
	return &Waste{Disks: d, Addresses: a, LBs: l, CVM: c}, nil
}

func str(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// Scan implements rightsize.WasteScanner.
func (w *Waste) Scan(ctx context.Context) ([]rightsize.WasteItem, error) {
	var out []rightsize.WasteItem
	var errs []error
	limit := uint64(100)
	for off := uint64(0); ; off += limit {
		req := cbs.NewDescribeDisksRequest()
		req.Offset, req.Limit = &off, &limit
		res, err := w.Disks.DescribeDisksWithContext(ctx, req)
		if err != nil {
			errs = append(errs, fmt.Errorf("DescribeDisks: %w", err))
			break
		}
		if res.Response == nil {
			break
		}
		for _, d := range res.Response.DiskSet {
			if d != nil && d.Attached != nil && !*d.Attached {
				size := uint64(0)
				if d.DiskSize != nil {
					size = *d.DiskSize
				}
				out = append(out, rightsize.WasteItem{ResourceID: str(d.DiskId), ResourceType: "disk", Kind: "unattached_disk",
					Detail: map[string]any{"size_gb": size, "disk_type": str(d.DiskType), "charge_type": str(d.DiskChargeType), "name": str(d.DiskName)}})
			}
		}
		if uint64(len(res.Response.DiskSet)) < limit {
			break
		}
	}
	ilimit := int64(100)
	for off := int64(0); ; off += ilimit {
		req := vpc.NewDescribeAddressesRequest()
		name, status := "address-status", "UNBIND"
		req.Filters = []*vpc.Filter{{Name: &name, Values: []*string{&status}}}
		req.Offset, req.Limit = &off, &ilimit
		res, err := w.Addresses.DescribeAddressesWithContext(ctx, req)
		if err != nil {
			errs = append(errs, fmt.Errorf("DescribeAddresses: %w", err))
			break
		}
		if res.Response == nil {
			break
		}
		for _, a := range res.Response.AddressSet {
			if a != nil && str(a.AddressStatus) == "UNBIND" {
				out = append(out, rightsize.WasteItem{ResourceID: str(a.AddressId), ResourceType: "eip", Kind: "unbound_eip", Detail: map[string]any{"ip": str(a.AddressIp)}})
			}
		}
		if int64(len(res.Response.AddressSet)) < ilimit {
			break
		}
	}
	lbs, err := w.LBs.DescribeLoadBalancersWithContext(ctx, clb.NewDescribeLoadBalancersRequest())
	if err != nil {
		errs = append(errs, fmt.Errorf("DescribeLoadBalancers: %w", err))
	} else if lbs.Response != nil {
		for _, lb := range lbs.Response.LoadBalancerSet {
			if lb == nil || lb.LoadBalancerId == nil {
				continue
			}
			req := clb.NewDescribeTargetsRequest()
			req.LoadBalancerId = lb.LoadBalancerId
			t, err := w.LBs.DescribeTargetsWithContext(ctx, req)
			if err != nil {
				errs = append(errs, fmt.Errorf("DescribeTargets %s: %w", *lb.LoadBalancerId, err))
				continue
			}
			if t.Response != nil && countTargets(t.Response.Listeners) == 0 {
				out = append(out, rightsize.WasteItem{ResourceID: *lb.LoadBalancerId, ResourceType: "clb", Kind: "empty_clb", Detail: map[string]any{"name": str(lb.LoadBalancerName)}})
			}
		}
	}
	req := cvm.NewDescribeInstancesRequest()
	name, state := "instance-state", "STOPPED"
	req.Filters = []*cvm.Filter{{Name: &name, Values: []*string{&state}}}
	ins, err := w.CVM.DescribeInstancesWithContext(ctx, req)
	if err != nil {
		errs = append(errs, fmt.Errorf("DescribeInstances: %w", err))
	} else if ins.Response != nil {
		for _, i := range ins.Response.InstanceSet {
			if i != nil && str(i.InstanceState) == "STOPPED" && str(i.StopChargingMode) == "KEEP_CHARGING" {
				out = append(out, rightsize.WasteItem{ResourceID: str(i.InstanceId), ResourceType: "vm", Kind: "stopped_paying",
					Detail: map[string]any{"note": "stopped but still charging; stop with StopChargingMode=STOP_CHARGING or terminate"}})
			}
		}
	}
	return out, errors.Join(errs...)
}

// countTargets counts backends across listeners and their rules.
func countTargets(ls []*clb.ListenerBackend) int {
	n := 0
	for _, l := range ls {
		if l == nil {
			continue
		}
		n += len(l.Targets)
		for _, r := range l.Rules {
			if r != nil {
				n += len(r.Targets)
			}
		}
	}
	return n
}

// CountTargets is exported for tests.
func CountTargets(ls []*clb.ListenerBackend) int { return countTargets(ls) }

// Delete implements rightsize.Cleaner: disks are snapshotted, then
// terminated (pay-as-you-go only); EIPs are released. Anything else is refused.
func (w *Waste) Delete(ctx context.Context, it rightsize.WasteItem) (string, error) {
	switch it.Kind {
	case "unattached_disk":
		d, err := w.Disks.DescribeDisksWithContext(ctx, &cbs.DescribeDisksRequest{DiskIds: []*string{&it.ResourceID}})
		if err != nil {
			return "", err
		}
		if d.Response == nil || len(d.Response.DiskSet) != 1 || d.Response.DiskSet[0].Attached == nil || *d.Response.DiskSet[0].Attached {
			return "", errors.New("disk is attached now or gone; not deleting")
		}
		if str(d.Response.DiskSet[0].DiskChargeType) != "POSTPAID_BY_HOUR" {
			return "", errors.New("only pay-as-you-go disks are deleted automatically")
		}
		name := "keel-before-delete-" + it.ResourceID
		snap, err := w.Disks.CreateSnapshotWithContext(ctx, &cbs.CreateSnapshotRequest{DiskId: &it.ResourceID, SnapshotName: &name})
		if err != nil {
			return "", fmt.Errorf("CreateSnapshot: %w", err)
		}
		id := ""
		if snap.Response != nil {
			id = str(snap.Response.SnapshotId)
		}
		if _, err := w.Disks.TerminateDisksWithContext(ctx, &cbs.TerminateDisksRequest{DiskIds: []*string{&it.ResourceID}}); err != nil {
			return id, fmt.Errorf("TerminateDisks: %w", err)
		}
		return id, nil
	case "unbound_eip":
		if _, err := w.Addresses.ReleaseAddressesWithContext(ctx, &vpc.ReleaseAddressesRequest{AddressIds: []*string{&it.ResourceID}}); err != nil {
			return "", fmt.Errorf("ReleaseAddresses: %w", err)
		}
		return "", nil
	}
	return "", fmt.Errorf("%s is not cleaned automatically", it.Kind)
}
