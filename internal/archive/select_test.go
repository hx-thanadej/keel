package archive_test

import (
	"strings"
	"testing"
	"time"

	"github.com/hx-thanadej/keel/internal/archive"
)

func envFrom(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestSelect(t *testing.T) {
	cosForms := map[string]string{
		"regional":               "cos.ap-bangkok.myqcloud.com",
		"bucket-host":            "mybucket-125000.cos.ap-bangkok.myqcloud.com",
		"tencentcos.cn":          "mybucket-125000.cos.ap-bangkok.tencentcos.cn",
		"tencentcos.cn bare":     "cos.ap-bangkok.tencentcos.cn",
		"accelerate":             "cos.accelerate.myqcloud.com",
		"bucket accelerate":      "mybucket-125000.cos.accelerate.myqcloud.com",
		"no region":              "cos.myqcloud.com",
		"https scheme":           "https://cos.ap-bangkok.myqcloud.com",
		"http scheme and port":   "http://cos.ap-bangkok.myqcloud.com:80",
		"port only":              "cos.ap-bangkok.myqcloud.com:443",
		"path and uppercase":     "HTTPS://COS.AP-BANGKOK.MYQCLOUD.COM/",
		"trailing dot":           "cos.ap-bangkok.myqcloud.com.",
		"tencentcos.cn w/scheme": "https://cos.accelerate.tencentcos.cn:443",
	}
	const hint = "KEEL_ARCHIVE_PROVIDER=tencent"

	t.Run("unset bucket disables archiving", func(t *testing.T) {
		sel, err := archive.Select(envFrom(map[string]string{"KEEL_ARCHIVE_PROVIDER": "bogus"}))
		if err != nil || sel.Bucket != "" {
			t.Fatalf("got %+v, %v; want disabled, nil", sel, err)
		}
	})

	t.Run("aws is the default", func(t *testing.T) {
		sel, err := archive.Select(envFrom(map[string]string{"KEEL_ARCHIVE_BUCKET": "b", "KEEL_ARCHIVE_REGION": "ap-southeast-1"}))
		want := archive.Selection{Provider: "aws", Bucket: "b", Region: "ap-southeast-1", Endpoint: "s3.ap-southeast-1.amazonaws.com", RetentionDays: archive.DefaultRetentionDays}
		if err != nil || sel != want {
			t.Fatalf("got %+v, %v; want %+v", sel, err, want)
		}
	})

	t.Run("aws needs a region", func(t *testing.T) {
		_, err := archive.Select(envFrom(map[string]string{"KEEL_ARCHIVE_BUCKET": "b"}))
		if err == nil || !strings.Contains(err.Error(), "KEEL_ARCHIVE_REGION") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("aws retention days parsed and validated", func(t *testing.T) {
		base := map[string]string{"KEEL_ARCHIVE_BUCKET": "b", "KEEL_ARCHIVE_REGION": "r"}
		base["KEEL_ARCHIVE_RETENTION_DAYS"] = "400"
		if sel, err := archive.Select(envFrom(base)); err != nil || sel.RetentionDays != 400 {
			t.Fatalf("got %+v, %v", sel, err)
		}
		base["KEEL_ARCHIVE_RETENTION_DAYS"] = "10"
		if _, err := archive.Select(envFrom(base)); err == nil {
			t.Fatal("retention below minimum accepted")
		}
	})

	t.Run("custom non-COS s3 endpoints stay allowed", func(t *testing.T) {
		for _, ep := range []string{
			"minio.internal:9000",
			"https://s3.example.com",
			"s3.ap-southeast-1.amazonaws.com",
			"myqcloud.com.example.com",
			"evilmyqcloud.com",
			"notcos.example.cn",
		} {
			sel, err := archive.Select(envFrom(map[string]string{"KEEL_ARCHIVE_BUCKET": "b", "KEEL_ARCHIVE_REGION": "r", "KEEL_ARCHIVE_ENDPOINT": ep}))
			if err != nil || sel.Endpoint != ep || sel.Provider != "aws" {
				t.Errorf("endpoint %q: got %+v, %v", ep, sel, err)
			}
		}
	})

	t.Run("COS endpoint with provider unset is refused", func(t *testing.T) {
		for name, ep := range cosForms {
			_, err := archive.Select(envFrom(map[string]string{"KEEL_ARCHIVE_BUCKET": "b", "KEEL_ARCHIVE_REGION": "ap-bangkok", "KEEL_ARCHIVE_ENDPOINT": ep}))
			if err == nil || !strings.Contains(err.Error(), hint) {
				t.Errorf("%s (%q): err = %v, want it to name %s", name, ep, err, hint)
			}
		}
	})

	t.Run("COS endpoint with explicit aws is refused", func(t *testing.T) {
		for name, ep := range cosForms {
			_, err := archive.Select(envFrom(map[string]string{"KEEL_ARCHIVE_PROVIDER": "aws", "KEEL_ARCHIVE_BUCKET": "b", "KEEL_ARCHIVE_REGION": "ap-bangkok", "KEEL_ARCHIVE_ENDPOINT": ep}))
			if err == nil || !strings.Contains(err.Error(), hint) {
				t.Errorf("%s (%q): err = %v, want it to name %s", name, ep, err, hint)
			}
		}
	})

	t.Run("explicit tencent keeps its COS endpoint and needs no retention", func(t *testing.T) {
		for _, ep := range cosForms {
			sel, err := archive.Select(envFrom(map[string]string{"KEEL_ARCHIVE_PROVIDER": "tencent", "KEEL_ARCHIVE_BUCKET": "b", "KEEL_ARCHIVE_REGION": "ap-bangkok", "KEEL_ARCHIVE_ENDPOINT": ep, "KEEL_ARCHIVE_RETENTION_DAYS": "junk"}))
			want := archive.Selection{Provider: "tencent", Bucket: "b", Region: "ap-bangkok", Endpoint: ep}
			if err != nil || sel != want {
				t.Errorf("%q: got %+v, %v; want %+v", ep, sel, err, want)
			}
		}
	})

	t.Run("unknown provider", func(t *testing.T) {
		_, err := archive.Select(envFrom(map[string]string{"KEEL_ARCHIVE_PROVIDER": "gcs", "KEEL_ARCHIVE_BUCKET": "b"}))
		if err == nil || !strings.Contains(err.Error(), "aws or tencent") {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestRetentionReport(t *testing.T) {
	until := time.Date(2033, 1, 2, 3, 4, 5, 0, time.UTC)
	lines, problems := archive.RetentionReport([]archive.Retention{
		{Key: "a", Mode: "COMPLIANCE", Until: until},
		{Key: "b"},
		{Key: "c", Mode: "GOVERNANCE", Until: until},
	})
	wantLines := []string{
		"RETENTION a COMPLIANCE until 2033-01-02T03:04:05Z",
		"RETENTION b none",
		"RETENTION c GOVERNANCE until 2033-01-02T03:04:05Z",
	}
	if strings.Join(lines, "\n") != strings.Join(wantLines, "\n") {
		t.Errorf("lines = %q", lines)
	}
	if len(problems) != 2 || !strings.HasPrefix(problems[0], "b:") || !strings.HasPrefix(problems[1], "c:") {
		t.Errorf("problems = %q, want b and c flagged, a not", problems)
	}
}
