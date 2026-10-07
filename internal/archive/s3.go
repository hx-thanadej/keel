package archive

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sort"
	"sync"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// S3Config configures an S3-compatible bucket (Tencent COS:
// Endpoint "cos.ap-bangkok.myqcloud.com").
type S3Config struct {
	Endpoint string
	Region   string
	Bucket   string
	Insecure bool // http instead of https (tests only)
	Creds    *credentials.Credentials
}

// S3 is an ObjectStore on an S3-compatible bucket.
type S3 struct {
	c      *minio.Client
	bucket string
}

// NewS3 connects to a bucket.
func NewS3(cfg S3Config) (*S3, error) {
	c, err := minio.New(cfg.Endpoint, &minio.Options{Creds: cfg.Creds, Secure: !cfg.Insecure, Region: cfg.Region, BucketLookup: minio.BucketLookupPath})
	if err != nil {
		return nil, err
	}
	return &S3{c: c, bucket: cfg.Bucket}, nil
}

// Put implements ObjectStore.
func (s *S3) Put(ctx context.Context, key string, body []byte, contentType string) error {
	_, err := s.c.PutObject(ctx, s.bucket, key, bytes.NewReader(body), int64(len(body)), minio.PutObjectOptions{ContentType: contentType})
	return err
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
