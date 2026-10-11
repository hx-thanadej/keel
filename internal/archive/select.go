package archive

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Selection is the archive configuration read from KEEL_ARCHIVE_*. An empty
// Bucket means archiving is off.
type Selection struct {
	Provider, Bucket, Region, Endpoint string
	RetentionDays                      int
}

// Select reads KEEL_ARCHIVE_* through getenv and decides the provider. It
// performs no I/O. A COS endpoint is refused unless the provider is
// explicitly tencent, so an upgrade that left the provider unset (default aws)
// cannot silently archive without Object Lock.
func Select(getenv func(string) string) (Selection, error) {
	sel := Selection{
		Bucket:   getenv("KEEL_ARCHIVE_BUCKET"),
		Region:   getenv("KEEL_ARCHIVE_REGION"),
		Endpoint: getenv("KEEL_ARCHIVE_ENDPOINT"),
		Provider: getenv("KEEL_ARCHIVE_PROVIDER"),
	}
	if sel.Bucket == "" {
		return Selection{}, nil
	}
	if sel.Provider == "" {
		sel.Provider = "aws"
	}
	switch sel.Provider {
	case "tencent":
		return sel, nil
	case "aws":
		if sel.Region == "" {
			return Selection{}, errors.New("KEEL_ARCHIVE_REGION is required with KEEL_ARCHIVE_BUCKET")
		}
		if sel.Endpoint == "" {
			sel.Endpoint = "s3." + sel.Region + ".amazonaws.com"
		}
		cos, err := isCOSEndpoint(sel.Endpoint)
		if err != nil {
			return Selection{}, fmt.Errorf("KEEL_ARCHIVE_ENDPOINT %q: %w", sel.Endpoint, err)
		}
		if cos {
			return Selection{}, fmt.Errorf("KEEL_ARCHIVE_ENDPOINT %q is a Tencent COS endpoint; set KEEL_ARCHIVE_PROVIDER=tencent for an existing COS archive", sel.Endpoint)
		}
		sel.RetentionDays, err = ParseRetentionDays(getenv("KEEL_ARCHIVE_RETENTION_DAYS"))
		if err != nil {
			return Selection{}, err
		}
		return sel, nil
	default:
		return Selection{}, fmt.Errorf("KEEL_ARCHIVE_PROVIDER must be aws or tencent, got %q", sel.Provider)
	}
}

// isCOSEndpoint reports whether endpoint (host, host:port or URL) is on a
// Tencent COS domain. It compares the parsed hostname, not the raw string.
func isCOSEndpoint(endpoint string) (bool, error) {
	raw := endpoint
	if !strings.Contains(raw, "://") {
		raw = "//" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return false, err
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	for _, domain := range []string{"myqcloud.com", "tencentcos.cn"} {
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return true, nil
		}
	}
	return false, nil
}

// RetentionReport renders one RETENTION line per object and lists a problem
// for each object not under COMPLIANCE retention.
func RetentionReport(rs []Retention) (lines, problems []string) {
	for _, o := range rs {
		if o.Mode == "" {
			lines = append(lines, "RETENTION "+o.Key+" none")
		} else {
			lines = append(lines, "RETENTION "+o.Key+" "+o.Mode+" until "+o.Until.Format(time.RFC3339))
		}
		if o.Mode != "COMPLIANCE" {
			problems = append(problems, o.Key+": not under COMPLIANCE Object Lock retention")
		}
	}
	return lines, problems
}
