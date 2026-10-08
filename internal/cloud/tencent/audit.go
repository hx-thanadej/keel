package tencent

import (
	"context"
	"fmt"
	"time"

	cloudaudit "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/cloudaudit/v20190319"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"

	"github.com/hx-thanadej/keel/internal/breakglass"
)

// AuditAPI is CloudAudit's event lookup.
type AuditAPI interface {
	LookUpEventsWithContext(context.Context, *cloudaudit.LookUpEventsRequest) (*cloudaudit.LookUpEventsResponse, error)
}

// CloudAudit implements breakglass.Audit for one account.
type CloudAudit struct {
	API AuditAPI
}

var _ breakglass.Audit = CloudAudit{}

// NewCloudAudit builds a CloudAudit client.
func NewCloudAudit(region string, creds common.Provider) (CloudAudit, error) {
	cred, err := creds.GetCredential()
	if err != nil {
		return CloudAudit{}, fmt.Errorf("tencent credentials: %w", err)
	}
	c, err := cloudaudit.NewClient(cred, region, profile.NewClientProfile())
	return CloudAudit{API: c}, err
}

// Events implements breakglass.Audit: calls made by the principal since a time.
func (a CloudAudit) Events(ctx context.Context, principalID string, since time.Time) ([]breakglass.Event, error) {
	var out []breakglass.Event
	var next *string
	for i := 0; i < 50; i++ {
		req := cloudaudit.NewLookUpEventsRequest()
		req.StartTime, req.EndTime = common.Int64Ptr(since.Unix()), common.Int64Ptr(time.Now().Unix())
		req.LookupAttributes = []*cloudaudit.LookupAttribute{{AttributeKey: common.StringPtr("PrincipalId"), AttributeValue: &principalID}}
		req.MaxResults, req.NextToken = common.Int64Ptr(50), next
		res, err := a.API.LookUpEventsWithContext(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("LookUpEvents: %w", err)
		}
		if res.Response == nil {
			break
		}
		for _, e := range res.Response.Events {
			if e == nil || e.EventId == nil {
				continue
			}
			at := time.Now()
			if e.EventTime != nil {
				if sec, err := parseUnix(*e.EventTime); err == nil {
					at = sec
				}
			}
			out = append(out, breakglass.Event{ID: *e.EventId, Name: deref(e.EventName), SourceIP: deref(e.SourceIPAddress), At: at})
		}
		if res.Response.ListOver != nil && *res.Response.ListOver {
			break
		}
		next = res.Response.NextToken
		if next == nil {
			break
		}
	}
	return out, nil
}

func parseUnix(s string) (time.Time, error) {
	var sec int64
	if _, err := fmt.Sscan(s, &sec); err != nil {
		return time.Time{}, err
	}
	return time.Unix(sec, 0), nil
}
