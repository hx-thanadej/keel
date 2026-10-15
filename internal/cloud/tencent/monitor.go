package tencent

import (
	"fmt"

	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	monitor "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/monitor/v20180724"
)

// NewMonitor builds a Cloud Monitor client for one account's credentials.
func NewMonitor(region string, creds common.Provider) (*monitor.Client, error) {
	cred, err := creds.GetCredential()
	if err != nil {
		return nil, fmt.Errorf("tencent credentials: %w", err)
	}
	return guard(monitor.NewClient(cred, region, profile.NewClientProfile()))
}
