package api

import (
	"errors"
	"io"
	"net/http"

	"github.com/hx-thanadej/keel/internal/auth"
	"github.com/hx-thanadej/keel/internal/authz"
	"github.com/hx-thanadej/keel/internal/catalog"
	"github.com/hx-thanadej/keel/internal/scans"
)

// ScanDeps serves scanner ingestion (#109).
type ScanDeps struct {
	Authz   catalog.Authorizer
	Service scans.Service
}

// maxSARIF bounds one upload.
const maxSARIF = 25 << 20

func mountScans(mux Mux, a auth.Authenticator, d ScanDeps) {
	mux.Handle("POST /v1/tenants/{tenant}/services/{service}/scans", authed(a, []string{"tenant", "service"}, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		tenant, service := r.PathValue("tenant"), r.PathValue("service")
		dec, err := d.Authz.Decide(r.Context(), authz.Request{Principal: p, Action: "scan.upload", Resource: authz.Resource{Type: "service", ID: service, TenantID: tenant}})
		if err != nil {
			return err
		}
		if !dec.Allow {
			return catalog.ErrForbidden
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, maxSARIF+1))
		if err != nil {
			return err
		}
		if len(body) > maxSARIF {
			return errors.Join(catalog.ErrInvalid, errors.New("SARIF larger than 25 MiB"))
		}
		q := r.URL.Query()
		u := scans.Upload{Scope: q.Get("scope"), CommitSHA: q.Get("commit"), Ref: q.Get("ref"), SARIF: body}
		if p.Pipeline != nil { // the token, not the caller, says which commit was scanned
			u.CommitSHA, u.Ref = p.Pipeline.SHA, p.Pipeline.Ref
		}
		out, err := d.Service.Ingest(r.Context(), tenant, service, u, actor(p))
		switch {
		case errors.Is(err, scans.ErrNotFound):
			return catalog.ErrNotFound
		case errors.Is(err, scans.ErrInvalid):
			return errors.Join(catalog.ErrInvalid, err)
		case err != nil:
			return err
		}
		writeJSON(w, http.StatusCreated, out)
		return nil
	}))
	mux.Handle("GET /v1/tenants/{tenant}/scans", authed(a, []string{"tenant"}, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		tenant := r.PathValue("tenant")
		dec, err := d.Authz.Decide(r.Context(), authz.Request{Principal: p, Action: "scan.read", Resource: authz.Resource{Type: "service", TenantID: tenant}})
		if err != nil {
			return err
		}
		if !dec.Allow {
			return catalog.ErrForbidden
		}
		svc := r.URL.Query().Get("service")
		if svc != "" && !catalog.ValidID(svc) {
			return errors.Join(catalog.ErrInvalid, errors.New("service must be a uuid"))
		}
		out, err := d.Service.Runs(r.Context(), tenant, svc)
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, items(out))
		return nil
	}))
}
