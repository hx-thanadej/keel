package tencent_test

import (
	"encoding/json"
	"testing"

	org "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/organization/v20210331"

	"github.com/hx-thanadej/keel/internal/cloud/tencent"
)

// Shape taken from the DescribeOrganizationMembers response model.
const member = `{"MemberUin": 200048351622, "Name": "tat-crm-prod", "NodeName": "TAT", "OrgPolicyType": "Financial",
	"PayUin": "200045645249", "Tags": [{"TagKey": "env", "TagValue": "prod"}]}`

func TestMemberAccount(t *testing.T) {
	var m org.OrgMember
	if err := json.Unmarshal([]byte(member), &m); err != nil {
		t.Fatal(err)
	}
	a := tencent.MemberAccount(&m)
	if a.Provider != "tencent" || a.ExternalID != "200048351622" || a.Name != "tat-crm-prod" || a.Parent != "TAT" || a.Tags["env"] != "prod" {
		t.Fatalf("got %+v", a)
	}
}
