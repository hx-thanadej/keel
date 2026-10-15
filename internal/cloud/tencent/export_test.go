package tencent

import "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"

var (
	StsClient = stsClient
	Reads     = reads
	Mints     = mints
)

// CommonClient is a guarded client for any service and action, so a test
// can send an action no Keel client exposes.
func CommonClient(cred common.CredentialIface, endpoint string) (*common.Client, error) {
	return guard(common.NewCommonClient(cred, "ap-bangkok", clientProfile(endpoint)), nil)
}
