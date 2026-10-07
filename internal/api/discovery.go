package api

import (
	"net/http"

	"github.com/hx-thanadej/keel/internal/auth"
	"github.com/hx-thanadej/keel/internal/catalog"
	"github.com/hx-thanadej/keel/internal/discovery"
)

func mountDiscovery(mux Mux, c *catalog.Service, a auth.Authenticator, sources map[string]discovery.Source) {
	mux.Handle("POST /v1/tenants/{tenant}/discoveries/{provider}", authed(a, []string{"tenant"}, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		src, ok := sources[r.PathValue("provider")]
		if !ok {
			writeJSON(w, http.StatusNotFound, errBody("no discovery source configured for "+r.PathValue("provider")))
			return nil
		}
		out, err := c.Discover(r.Context(), p, r.PathValue("tenant"), src)
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, items(out))
		return nil
	}))
	mux.Handle("GET /v1/tenants/{tenant}/discovered-accounts", authed(a, []string{"tenant"}, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		out, err := c.ListDiscovered(r.Context(), p, r.PathValue("tenant"))
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, items(out))
		return nil
	}))
}
