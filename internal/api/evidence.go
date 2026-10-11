package api

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/hx-thanadej/keel/internal/auth"
	"github.com/hx-thanadej/keel/internal/authz"
	"github.com/hx-thanadej/keel/internal/catalog"
	"github.com/hx-thanadej/keel/internal/evidence"
)

// EvidenceDeps serves evidence export (#151), for every framework or one
// named by ?framework= (#191).
type EvidenceDeps struct {
	Authz    catalog.Authorizer
	Exporter evidence.Exporter
}

func mountEvidence(mux Mux, a auth.Authenticator, d EvidenceDeps) {
	mux.Handle("GET /v1/tenants/{tenant}/evidence", authed(a, []string{"tenant"}, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		tenant := r.PathValue("tenant")
		dec, err := d.Authz.Decide(r.Context(), authz.Request{Principal: p, Action: "evidence.export", Resource: authz.Resource{Type: "evidence", TenantID: tenant}})
		if err != nil {
			return err
		}
		if !dec.Allow {
			return catalog.ErrForbidden
		}
		q := r.URL.Query()
		from, err1 := time.Parse("2006-01-02", q.Get("from"))
		to, err2 := time.Parse("2006-01-02", q.Get("to"))
		if err1 != nil || err2 != nil || !from.Before(to) {
			return errors.Join(catalog.ErrInvalid, errors.New("from and to are YYYY-MM-DD, from before to"))
		}
		b, err := d.Exporter.Export(r.Context(), tenant, q.Get("framework"), from, to, actor(p))
		if errors.Is(err, evidence.ErrNoKey) || errors.Is(err, evidence.ErrUnknownFramework) {
			return errors.Join(catalog.ErrInvalid, err)
		}
		if err != nil {
			return err
		}
		name := "keel-evidence-"
		if f := q.Get("framework"); f != "" {
			name += strings.ToLower(f) + "-"
		}
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s%s-%s.json"`, name, q.Get("from"), q.Get("to")))
		writeJSON(w, http.StatusOK, b)
		return nil
	}))
}
