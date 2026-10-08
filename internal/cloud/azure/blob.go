// Package azure reads Azure Cost Management FOCUS exports from Blob Storage
// with Entra workload identity federation: Keel presents its projected
// Kubernetes service-account token as a client assertion and receives a
// short-lived access token, so no client secret or storage key exists
// (ADR-0007).
package azure

import (
	"bytes"
	"context"
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

// Federated exchanges a federated OIDC token for an Entra access token. It
// reads the standard workload identity variables when fields are empty:
// AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_FEDERATED_TOKEN_FILE and
// AZURE_AUTHORITY_HOST.
type Federated struct {
	TenantID, ClientID, TokenFile, Authority string
	Scope                                    string
	HTTP                                     *http.Client

	mu      sync.Mutex
	token   string
	expires time.Time
}

// FromEnv fills a Federated from the workload identity environment.
func FromEnv(scope string) (*Federated, error) {
	f := &Federated{TenantID: os.Getenv("AZURE_TENANT_ID"), ClientID: os.Getenv("AZURE_CLIENT_ID"),
		TokenFile: os.Getenv("AZURE_FEDERATED_TOKEN_FILE"), Authority: os.Getenv("AZURE_AUTHORITY_HOST"), Scope: scope}
	if f.TenantID == "" || f.ClientID == "" || f.TokenFile == "" {
		return nil, errors.New("azure: AZURE_TENANT_ID, AZURE_CLIENT_ID and AZURE_FEDERATED_TOKEN_FILE are required (workload identity)")
	}
	return f, nil
}

// Token returns a cached access token, renewing 5 minutes before expiry.
// The assertion file is re-read each time because the kubelet rotates it.
func (f *Federated) Token(ctx context.Context) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.token != "" && time.Until(f.expires) > 5*time.Minute {
		return f.token, nil
	}
	assertion, err := os.ReadFile(f.TokenFile)
	if err != nil {
		return "", fmt.Errorf("azure: federated token: %w", err)
	}
	authority := strings.TrimSuffix(f.Authority, "/")
	if authority == "" {
		authority = "https://login.microsoftonline.com"
	}
	form := url.Values{
		"grant_type":            {"client_credentials"},
		"client_id":             {f.ClientID},
		"scope":                 {f.Scope},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {strings.TrimSpace(string(assertion))},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, authority+"/"+url.PathEscape(f.TenantID)+"/oauth2/v2.0/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := client(f.HTTP).Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = res.Body.Close() }()
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&out); err != nil {
		return "", fmt.Errorf("azure token: %s: %w", res.Status, err)
	}
	if res.StatusCode != http.StatusOK || out.AccessToken == "" {
		return "", fmt.Errorf("azure token: %s %s %s", res.Status, out.Error, firstLine(out.Description))
	}
	f.token, f.expires = out.AccessToken, time.Now().Add(time.Duration(out.ExpiresIn)*time.Second)
	return f.token, nil
}

// Blob lists and reads one container (cost.Objects with ETags).
type Blob struct {
	Account, Container string
	Endpoint           string // default https://<account>.blob.core.windows.net
	Auth               interface {
		Token(ctx context.Context) (string, error)
	}
	HTTP *http.Client
}

// StorageScope is the Entra scope for Blob Storage.
const StorageScope = "https://storage.azure.com/.default"

func (b Blob) base() string {
	if b.Endpoint != "" {
		return strings.TrimSuffix(b.Endpoint, "/")
	}
	return "https://" + b.Account + ".blob.core.windows.net"
}

func (b Blob) do(ctx context.Context, u string) (*http.Response, error) {
	tok, err := b.Auth.Token(ctx)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("x-ms-version", "2023-11-03")
	res, err := client(b.HTTP).Do(req)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 64<<10))
		_ = res.Body.Close()
		var e struct {
			Code    string `xml:"Code"`
			Message string `xml:"Message"`
		}
		_ = xml.Unmarshal(bytes.TrimPrefix(body, []byte("\ufeff")), &e)
		return nil, fmt.Errorf("azure blob %s: %s %s", res.Status, e.Code, firstLine(e.Message))
	}
	return res, nil
}

// ListWithETag lists blobs under prefix, following continuation markers.
func (b Blob) ListWithETag(ctx context.Context, prefix string) ([]cost.ObjectInfo, error) {
	var out []cost.ObjectInfo
	marker := ""
	for {
		q := url.Values{"restype": {"container"}, "comp": {"list"}, "prefix": {prefix}}
		if marker != "" {
			q.Set("marker", marker)
		}
		res, err := b.do(ctx, b.base()+"/"+url.PathEscape(b.Container)+"?"+q.Encode())
		if err != nil {
			return nil, err
		}
		var page struct {
			Blobs []struct {
				Name       string `xml:"Name"`
				Properties struct {
					ETag string `xml:"Etag"`
				} `xml:"Properties"`
			} `xml:"Blobs>Blob"`
			NextMarker string `xml:"NextMarker"`
		}
		err = xml.NewDecoder(io.LimitReader(res.Body, 64<<20)).Decode(&page)
		_ = res.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("azure blob list: %w", err)
		}
		for _, bl := range page.Blobs {
			out = append(out, cost.ObjectInfo{Key: bl.Name, ETag: strings.Trim(bl.Properties.ETag, `"`)})
		}
		if page.NextMarker == "" {
			return out, nil
		}
		marker = page.NextMarker
	}
}

// List lists blob names under prefix.
func (b Blob) List(ctx context.Context, prefix string) ([]string, error) {
	objs, err := b.ListWithETag(ctx, prefix)
	keys := make([]string, len(objs))
	for i, o := range objs {
		keys[i] = o.Key
	}
	return keys, err
}

// Get reads a blob (bill files are bounded at 4 GiB).
func (b Blob) Get(ctx context.Context, key string) ([]byte, error) {
	segs := strings.Split(key, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	res, err := b.do(ctx, b.base()+"/"+url.PathEscape(b.Container)+"/"+strings.Join(segs, "/"))
	if err != nil {
		return nil, err
	}
	defer func() { _ = res.Body.Close() }()
	return io.ReadAll(io.LimitReader(res.Body, 4<<30))
}

func client(c *http.Client) *http.Client {
	if c != nil {
		return c
	}
	return &http.Client{Timeout: 5 * time.Minute}
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(strings.TrimSpace(s), "\n")
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}
