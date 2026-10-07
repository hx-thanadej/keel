package tencent_test

import (
	"encoding/json"
	"testing"

	clb "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/clb/v20180317"

	"github.com/hx-thanadej/keel/internal/cloud/tencent"
)

func TestCountTargets(t *testing.T) {
	// DescribeTargets shape: layer-4 listener targets + layer-7 rule targets.
	raw := `[{"ListenerId":"lbl-1","Protocol":"TCP","Targets":[{"InstanceId":"ins-1","Port":80}]},
	         {"ListenerId":"lbl-2","Protocol":"HTTP","Rules":[{"LocationId":"loc-1","Targets":[{"InstanceId":"ins-2","Port":8080},{"InstanceId":"ins-3","Port":8080}]}]},
	         {"ListenerId":"lbl-3","Protocol":"HTTPS","Rules":[{"LocationId":"loc-2","Targets":[]}]}]`
	var ls []*clb.ListenerBackend
	if err := json.Unmarshal([]byte(raw), &ls); err != nil {
		t.Fatal(err)
	}
	if n := tencent.CountTargets(ls); n != 3 {
		t.Fatalf("targets %d", n)
	}
	if tencent.CountTargets(nil) != 0 {
		t.Fatal("empty")
	}
}
