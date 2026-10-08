// Package alibaba reads Alibaba Cloud bill files from OSS with RRSA: Keel
// exchanges its projected service-account token for STS credentials through
// AssumeRoleWithOIDC, so no AccessKey pair exists (ADR-0007).
package alibaba

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/hx-thanadej/keel/internal/cost"
)

// Credentials are STS credentials.
type Credentials struct {
	AccessKeyID, AccessKeySecret, SecurityToken string
	Expiration                                  time.Time
}

// RRSA assumes a RAM role with an OIDC token. Empty fields come from the
// standard ACK RRSA variables ALIBABA_CLOUD_ROLE_ARN,
// ALIBABA_CLOUD_OIDC_PROVIDER_ARN and ALIBABA_CLOUD_OIDC_TOKEN_FILE.
type RRSA struct {
	RoleArn, ProviderArn, TokenFile string
	Endpoint                        string // default https://sts.aliyuncs.com
	HTTP                            *http.Client
	Now                             func() time.Time

	mu     sync.Mutex
	cached *Credentials
}

// RRSAFromEnv fills an RRSA from the ACK environment.
func RRSAFromEnv() (*RRSA, error) {
	r := &RRSA{RoleArn: os.Getenv("ALIBABA_CLOUD_ROLE_ARN"), ProviderArn: os.Getenv("ALIBABA_CLOUD_OIDC_PROVIDER_ARN"), TokenFile: os.Getenv("ALIBABA_CLOUD_OIDC_TOKEN_FILE")}
	if r.RoleArn == "" || r.ProviderArn == "" || r.TokenFile == "" {
		return nil, errors.New("alibaba: ALIBABA_CLOUD_ROLE_ARN, ALIBABA_CLOUD_OIDC_PROVIDER_ARN and ALIBABA_CLOUD_OIDC_TOKEN_FILE are required (RRSA)")
	}
	return r, nil
}

func (r *RRSA) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// Credentials returns cached STS credentials, renewing 5 minutes before expiry.
func (r *RRSA) Credentials(ctx context.Context) (Credentials, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cached != nil && r.cached.Expiration.Sub(r.now()) > 5*time.Minute {
		return *r.cached, nil
	}
	tok, err := os.ReadFile(r.TokenFile)
	if err != nil {
		return Credentials{}, fmt.Errorf("alibaba: oidc token: %w", err)
	}
	endpoint := r.Endpoint
	if endpoint == "" {
		endpoint = "https://sts.aliyuncs.com"
	}
	form := url.Values{
		"Action": {"AssumeRoleWithOIDC"}, "Version": {"2015-04-01"}, "Format": {"JSON"},
		"Timestamp": {r.now().UTC().Format("2006-01-02T15:04:05Z")},
		"RoleArn":   {r.RoleArn}, "OIDCProviderArn": {r.ProviderArn}, "OIDCToken": {strings.TrimSpace(string(tok))},
		"RoleSessionName": {"keel"}, "DurationSeconds": {"3600"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return Credentials{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := httpClient(r.HTTP).Do(req)
	if err != nil {
		return Credentials{}, err
	}
	defer func() { _ = res.Body.Close() }()
	var out struct {
		Credentials struct {
			AccessKeyID     string `json:"AccessKeyId"`
			AccessKeySecret string `json:"AccessKeySecret"`
			SecurityToken   string `json:"SecurityToken"`
			Expiration      string `json:"Expiration"`
		} `json:"Credentials"`
		Code    string `json:"Code"`
		Message string `json:"Message"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&out); err != nil {
		return Credentials{}, fmt.Errorf("alibaba sts: %s: %w", res.Status, err)
	}
	if res.StatusCode != http.StatusOK || out.Credentials.AccessKeyID == "" {
		return Credentials{}, fmt.Errorf("alibaba sts: %s %s %s", res.Status, out.Code, out.Message)
	}
	exp, err := time.Parse(time.RFC3339, out.Credentials.Expiration)
	if err != nil {
		return Credentials{}, fmt.Errorf("alibaba sts: expiration %q: %w", out.Credentials.Expiration, err)
	}
	r.cached = &Credentials{AccessKeyID: out.Credentials.AccessKeyID, AccessKeySecret: out.Credentials.AccessKeySecret,
		SecurityToken: out.Credentials.SecurityToken, Expiration: exp}
	return *r.cached, nil
}

// OSS lists and reads one bucket (cost.Objects with ETags), signing requests
// with OSS signature V1 and the STS security token.
type OSS struct {
	Bucket, Region string
	Endpoint       string // default https://<bucket>.oss-<region>.aliyuncs.com
	Creds          interface {
		Credentials(ctx context.Context) (Credentials, error)
	}
	HTTP *http.Client
	Now  func() time.Time
}

func (o OSS) base() string {
	if o.Endpoint != "" {
		return strings.TrimSuffix(o.Endpoint, "/")
	}
	return "https://" + o.Bucket + ".oss-" + o.Region + ".aliyuncs.com"
}

// sign computes the V1 Authorization for a GET of resource (/bucket/key).
func sign(c Credentials, date, resource string) string {
	toSign := "GET\n\n\n" + date + "\n" + "x-oss-security-token:" + c.SecurityToken + "\n" + resource
	m := hmac.New(sha1.New, []byte(c.AccessKeySecret))
	m.Write([]byte(toSign))
	return "OSS " + c.AccessKeyID + ":" + base64.StdEncoding.EncodeToString(m.Sum(nil))
}

func (o OSS) get(ctx context.Context, path, rawQuery, resource string) (*http.Response, error) {
	c, err := o.Creds.Credentials(ctx)
	if err != nil {
		return nil, err
	}
	u := o.base() + path
	if rawQuery != "" {
		u += "?" + rawQuery
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	now := time.Now
	if o.Now != nil {
		now = o.Now
	}
	date := now().UTC().Format(http.TimeFormat)
	req.Header.Set("Date", date)
	req.Header.Set("x-oss-security-token", c.SecurityToken)
	req.Header.Set("Authorization", sign(c, date, resource))
	res, err := httpClient(o.HTTP).Do(req)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		_ = res.Body.Close()
		return nil, fmt.Errorf("oss %s: %s", res.Status, strings.TrimSpace(string(body)))
	}
	return res, nil
}

// ListWithETag lists objects under prefix (ListObjects, following markers;
// prefix and marker are not signed subresources).
func (o OSS) ListWithETag(ctx context.Context, prefix string) ([]cost.ObjectInfo, error) {
	var out []cost.ObjectInfo
	marker := ""
	for {
		q := url.Values{"prefix": {prefix}, "max-keys": {"1000"}}
		if marker != "" {
			q.Set("marker", marker)
		}
		res, err := o.get(ctx, "/", q.Encode(), "/"+o.Bucket+"/")
		if err != nil {
			return nil, err
		}
		var page struct {
			IsTruncated bool   `xml:"IsTruncated"`
			NextMarker  string `xml:"NextMarker"`
			Contents    []struct {
				Key  string `xml:"Key"`
				ETag string `xml:"ETag"`
			} `xml:"Contents"`
		}
		err = xml.NewDecoder(io.LimitReader(res.Body, 64<<20)).Decode(&page)
		_ = res.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("oss list: %w", err)
		}
		for _, c := range page.Contents {
			out = append(out, cost.ObjectInfo{Key: c.Key, ETag: strings.Trim(c.ETag, `"`)})
		}
		if !page.IsTruncated || page.NextMarker == "" {
			return out, nil
		}
		marker = page.NextMarker
	}
}

// List lists object keys under prefix.
func (o OSS) List(ctx context.Context, prefix string) ([]string, error) {
	objs, err := o.ListWithETag(ctx, prefix)
	keys := make([]string, len(objs))
	for i, ob := range objs {
		keys[i] = ob.Key
	}
	return keys, err
}

// Get reads an object.
func (o OSS) Get(ctx context.Context, key string) ([]byte, error) {
	segs := strings.Split(key, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	res, err := o.get(ctx, "/"+strings.Join(segs, "/"), "", "/"+o.Bucket+"/"+key)
	if err != nil {
		return nil, err
	}
	defer func() { _ = res.Body.Close() }()
	return io.ReadAll(io.LimitReader(res.Body, 4<<30))
}

func httpClient(c *http.Client) *http.Client {
	if c != nil {
		return c
	}
	return &http.Client{Timeout: 5 * time.Minute}
}
