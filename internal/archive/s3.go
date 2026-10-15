package archive

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// S3Config configures an S3-compatible bucket (AWS S3:
// Endpoint "s3.ap-southeast-1.amazonaws.com"; Tencent COS:
// Endpoint "cos.ap-bangkok.myqcloud.com").
type S3Config struct {
	Endpoint string
	Region   string
	Bucket   string
	Insecure bool // http instead of https (tests only)
	Creds    *credentials.Credentials
	// RetentionDays, when non-zero, writes every object under S3 Object Lock
	// in COMPLIANCE mode until now + RetentionDays (ADR-0019).
	RetentionDays int
}

// DefaultRetentionDays is seven years (DESIGN §8).
const DefaultRetentionDays = 2555

// MinRetentionDays is the shortest Object Lock retention Keel accepts.
const MinRetentionDays = 365

// ParseRetentionDays reads KEEL_ARCHIVE_RETENTION_DAYS. Empty means the default.
func ParseRetentionDays(s string) (int, error) {
	if s == "" {
		return DefaultRetentionDays, nil
	}
	d, err := strconv.Atoi(s)
	if err != nil || d < MinRetentionDays {
		return 0, fmt.Errorf("KEEL_ARCHIVE_RETENTION_DAYS must be a whole number of days >= %d, got %q", MinRetentionDays, s)
	}
	return d, nil
}

// S3 is an ObjectStore on an S3-compatible bucket.
type S3 struct {
	c             *minio.Client
	bucket        string
	retentionDays int
}

// NewS3 connects to a bucket.
func NewS3(cfg S3Config) (*S3, error) {
	if cfg.RetentionDays != 0 && cfg.RetentionDays < MinRetentionDays {
		return nil, fmt.Errorf("object lock retention must be >= %d days, got %d", MinRetentionDays, cfg.RetentionDays)
	}
	return newS3(cfg, nil)
}

func newS3(cfg S3Config, transport http.RoundTripper) (*S3, error) {
	c, err := minio.New(cfg.Endpoint, &minio.Options{Creds: cfg.Creds, Secure: !cfg.Insecure, Region: cfg.Region, BucketLookup: minio.BucketLookupPath,
		Transport: transport})
	if err != nil {
		return nil, err
	}
	return &S3{c: c, bucket: cfg.Bucket, retentionDays: cfg.RetentionDays}, nil
}

// ErrReadOnly is a write refused by a Reader.
var ErrReadOnly = errors.New("refused: this bucket client only reads")

// Reader reads a bucket and cannot write to it: it has no write method, and
// its transport refuses any request but GET and HEAD before it leaves
// Keel. Bill and COS reads use it, so a read-only identity's credentials
// never reach a client that could write (ADR-0022).
type Reader struct{ s *S3 }

// NewReader connects to a bucket for reading.
func NewReader(cfg S3Config) (*Reader, error) {
	next, err := minio.DefaultTransport(!cfg.Insecure)
	if err != nil {
		return nil, err
	}
	s, err := newS3(S3Config{Endpoint: cfg.Endpoint, Region: cfg.Region, Bucket: cfg.Bucket, Insecure: cfg.Insecure, Creds: cfg.Creds}, getsOnly{next})
	if err != nil {
		return nil, err
	}
	return &Reader{s: s}, nil
}

// Get returns one object.
func (r *Reader) Get(ctx context.Context, key string) ([]byte, error) { return r.s.Get(ctx, key) }

// List lists keys under prefix.
func (r *Reader) List(ctx context.Context, prefix string) ([]string, error) {
	return r.s.List(ctx, prefix)
}

// ListWithETag lists keys under prefix with their ETags.
func (r *Reader) ListWithETag(ctx context.Context, prefix string) ([]ObjectVersion, error) {
	return r.s.ListWithETag(ctx, prefix)
}

type getsOnly struct{ next http.RoundTripper }

func (g getsOnly) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		if r.Body != nil {
			_ = r.Body.Close()
		}
		return nil, fmt.Errorf("%s %s: %w", r.Method, r.URL.Path, ErrReadOnly)
	}
	return g.next.RoundTrip(r)
}

// Put implements ObjectStore.
func (s *S3) Put(ctx context.Context, key string, body []byte, contentType string) error {
	opts := minio.PutObjectOptions{ContentType: contentType}
	if s.retentionDays > 0 {
		opts.Mode = minio.Compliance
		opts.RetainUntilDate = time.Now().UTC().AddDate(0, 0, s.retentionDays).Truncate(time.Second)
		// S3 rejects an Object Lock PUT without Content-MD5 or an x-amz-checksum header.
		opts.SendContentMd5 = true
	}
	_, err := s.c.PutObject(ctx, s.bucket, key, bytes.NewReader(body), int64(len(body)), opts)
	return err
}

// RequireObjectLock fails unless the bucket has Object Lock and versioning
// enabled. Object Lock can only be turned on at bucket creation (or by AWS
// support), so a bucket without it can never become WORM by Keel's writes.
func (s *S3) RequireObjectLock(ctx context.Context) error {
	enabled, _, _, _, err := s.c.GetObjectLockConfig(ctx, s.bucket)
	if err != nil {
		return fmt.Errorf("archive bucket %s: reading Object Lock configuration: %w (the bucket must be created with Object Lock enabled)", s.bucket, err)
	}
	if enabled != "Enabled" {
		return fmt.Errorf("archive bucket %s does not have Object Lock enabled (ObjectLockEnabled=%q)", s.bucket, enabled)
	}
	v, err := s.c.GetBucketVersioning(ctx, s.bucket)
	if err != nil {
		return fmt.Errorf("archive bucket %s: reading versioning: %w", s.bucket, err)
	}
	if !v.Enabled() {
		return fmt.Errorf("archive bucket %s does not have versioning enabled (Status=%q)", s.bucket, v.Status)
	}
	return nil
}

// Retention is an object's Object Lock retention. Mode is empty when the
// object has none.
type Retention struct {
	Key   string
	Mode  string
	Until time.Time
}

// Retentions reports the retention of every object under prefix.
func (s *S3) Retentions(ctx context.Context, prefix string) ([]Retention, error) {
	keys, err := s.List(ctx, prefix)
	if err != nil {
		return nil, err
	}
	out := make([]Retention, 0, len(keys))
	for _, k := range keys {
		r := Retention{Key: k}
		mode, until, err := s.c.GetObjectRetention(ctx, s.bucket, k, "")
		var resp minio.ErrorResponse
		switch {
		case errors.As(err, &resp) && resp.Code == "NoSuchObjectLockConfiguration":
		case err != nil:
			return nil, fmt.Errorf("retention of %s: %w", k, err)
		default:
			if mode != nil {
				r.Mode = mode.String()
			}
			if until != nil {
				r.Until = until.UTC()
			}
		}
		out = append(out, r)
	}
	return out, nil
}

// Get implements ObjectStore.
func (s *S3) Get(ctx context.Context, key string) ([]byte, error) {
	o, err := s.c.GetObject(ctx, s.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, err
	}
	defer func() { _ = o.Close() }()
	b, err := io.ReadAll(o)
	if err != nil {
		var resp minio.ErrorResponse
		if errors.As(err, &resp) && resp.Code == "NoSuchKey" {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return b, nil
}

// List implements ObjectStore.
func (s *S3) List(ctx context.Context, prefix string) ([]string, error) {
	var out []string
	for o := range s.c.ListObjects(ctx, s.bucket, minio.ListObjectsOptions{Prefix: prefix, Recursive: true}) {
		if o.Err != nil {
			return nil, o.Err
		}
		out = append(out, o.Key)
	}
	sort.Strings(out)
	return out, nil
}

// StaticCreds wraps fixed credentials (tests, or short-lived values a caller refreshes).
func StaticCreds(id, secret, token string) *credentials.Credentials {
	return credentials.NewStaticV4(id, secret, token)
}

// TemporaryCredentials is anything that yields (id, key, session token) on
// demand, e.g. a Tencent Cloud STS provider (TKE pod identity, CVM role).
type TemporaryCredentials interface {
	Get() (id, key, token string, err error)
}

// Refreshing adapts TemporaryCredentials to the S3 client, refetching every
// refresh interval so keyless, short-lived credentials are used (ADR-0007).
func Refreshing(src TemporaryCredentials, refresh time.Duration) *credentials.Credentials {
	return credentials.New(&refreshing{src: src, every: refresh})
}

type refreshing struct {
	src   TemporaryCredentials
	every time.Duration
	mu    sync.Mutex
	at    time.Time
}

func (r *refreshing) RetrieveWithCredContext(*credentials.CredContext) (credentials.Value, error) {
	return r.Retrieve()
}

func (r *refreshing) Retrieve() (credentials.Value, error) {
	id, key, token, err := r.src.Get()
	if err != nil {
		return credentials.Value{}, err
	}
	r.mu.Lock()
	r.at = time.Now()
	r.mu.Unlock()
	return credentials.Value{AccessKeyID: id, SecretAccessKey: key, SessionToken: token, SignerType: credentials.SignatureV4}, nil
}

func (r *refreshing) IsExpired() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return time.Since(r.at) > r.every
}

// ListWithETag lists keys with their ETags, so rewritten files are detected.
func (s *S3) ListWithETag(ctx context.Context, prefix string) ([]ObjectVersion, error) {
	var out []ObjectVersion
	for o := range s.c.ListObjects(ctx, s.bucket, minio.ListObjectsOptions{Prefix: prefix, Recursive: true}) {
		if o.Err != nil {
			return nil, o.Err
		}
		out = append(out, ObjectVersion{Key: o.Key, ETag: o.ETag})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

// ObjectVersion is a key and its ETag.
type ObjectVersion struct{ Key, ETag string }
