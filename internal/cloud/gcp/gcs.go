// Package gcp reads Google Cloud FOCUS exports from Cloud Storage. Keel
// authenticates with Application Default Credentials restricted to keyless
// kinds: the GKE metadata server, workload identity federation
// (external_account), or impersonation whose source is itself keyless.
// Service-account keys, user refresh tokens and unknown types are refused
// (ADR-0007).
package gcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/hx-thanadej/keel/internal/cost"
)

// ReadOnlyScope is the Cloud Storage read scope.
const ReadOnlyScope = "https://www.googleapis.com/auth/devstorage.read_only"

// ErrKeyFile means ADC resolved to something other than a keyless credential.
var ErrKeyFile = errors.New("gcp: only keyless credentials are allowed (metadata server, external_account, or impersonation from one); use workload identity federation")

// Keyless returns a token source from Application Default Credentials,
// refusing anything that carries a long-lived secret.
func Keyless(ctx context.Context, scopes ...string) (oauth2.TokenSource, error) {
	creds, err := google.FindDefaultCredentials(ctx, scopes...)
	if err != nil {
		return nil, err
	}
	if err := checkKeyless(creds.JSON); err != nil {
		return nil, err
	}
	return creds.TokenSource, nil
}

type adcFile struct {
	Type   string   `json:"type"`
	Source *adcFile `json:"source_credentials"`
}

// checkKeyless allow-lists keyless ADC shapes. Errors name the credential
// types only, never the file's content.
func checkKeyless(raw []byte) error {
	if len(raw) == 0 {
		return nil // metadata server
	}
	var f adcFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return fmt.Errorf("%w (credentials file is not valid JSON)", ErrKeyFile)
	}
	chain := []string{}
	for c := &f; ; c = c.Source {
		if c == nil {
			return fmt.Errorf("%w (%s without source_credentials)", ErrKeyFile, strings.Join(chain, " wrapping "))
		}
		chain = append(chain, strconv.Quote(c.Type))
		switch c.Type {
		case "external_account":
			return nil
		case "impersonated_service_account":
			continue
		}
		return fmt.Errorf("%w (got %s)", ErrKeyFile, strings.Join(chain, " wrapping "))
	}
}

// GCS lists and reads one bucket through the JSON API (cost.Objects with
// ETags; generation is the content version).
type GCS struct {
	Bucket   string
	Endpoint string // default https://storage.googleapis.com
	Tokens   oauth2.TokenSource
	HTTP     *http.Client
}

func (g GCS) base() string {
	if g.Endpoint != "" {
		return strings.TrimSuffix(g.Endpoint, "/")
	}
	return "https://storage.googleapis.com"
}

func (g GCS) do(ctx context.Context, u string) (*http.Response, error) {
	tok, err := g.Tokens.Token()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	tok.SetAuthHeader(req)
	c := g.HTTP
	if c == nil {
		c = &http.Client{Timeout: 5 * time.Minute}
	}
	res, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		var body struct {
			Error struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = json.NewDecoder(io.LimitReader(res.Body, 64<<10)).Decode(&body)
		_ = res.Body.Close()
		return nil, fmt.Errorf("gcs %s: %s", res.Status, clip(body.Error.Message))
	}
	return res, nil
}

// ListWithETag lists objects under prefix, following page tokens.
func (g GCS) ListWithETag(ctx context.Context, prefix string) ([]cost.ObjectInfo, error) {
	var out []cost.ObjectInfo
	page := ""
	for {
		q := url.Values{"prefix": {prefix}, "fields": {"items(name,generation),nextPageToken"}}
		if page != "" {
			q.Set("pageToken", page)
		}
		res, err := g.do(ctx, g.base()+"/storage/v1/b/"+url.PathEscape(g.Bucket)+"/o?"+q.Encode())
		if err != nil {
			return nil, err
		}
		var body struct {
			Items []struct {
				Name       string `json:"name"`
				Generation string `json:"generation"`
			} `json:"items"`
			NextPageToken string `json:"nextPageToken"`
		}
		err = json.NewDecoder(io.LimitReader(res.Body, 64<<20)).Decode(&body)
		_ = res.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("gcs list: %w", err)
		}
		for _, it := range body.Items {
			out = append(out, cost.ObjectInfo{Key: it.Name, ETag: it.Generation})
		}
		if body.NextPageToken == "" {
			return out, nil
		}
		page = body.NextPageToken
	}
}

// List lists object names under prefix.
func (g GCS) List(ctx context.Context, prefix string) ([]string, error) {
	objs, err := g.ListWithETag(ctx, prefix)
	keys := make([]string, len(objs))
	for i, o := range objs {
		keys[i] = o.Key
	}
	return keys, err
}

// Get reads an object's content.
func (g GCS) Get(ctx context.Context, key string) ([]byte, error) {
	res, err := g.do(ctx, g.base()+"/storage/v1/b/"+url.PathEscape(g.Bucket)+"/o/"+url.PathEscape(key)+"?alt=media")
	if err != nil {
		return nil, err
	}
	defer func() { _ = res.Body.Close() }()
	return io.ReadAll(io.LimitReader(res.Body, 4<<30))
}

// clip keeps an error message to one bounded line.
func clip(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}
