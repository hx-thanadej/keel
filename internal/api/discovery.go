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
	mux.Handle("POST /v1/tenants/{tenant}/cloud-accounts/register", authed(a, []string{"tenant"}, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		var in struct {
			TeamID   string                 `json:"team_id"`
			Why      string                 `json:"why"`
			Accounts []catalog.Registration `json:"accounts"`
		}
		if err := decode(r, &in); err != nil {
			return err
		}
		if in.Why == "" {
			in.Why = "registered from discovered accounts"
		}
		out, err := c.RegisterAccounts(r.Context(), p, r.PathValue("tenant"), in.TeamID, in.Accounts, in.Why)
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, items(out))
		return nil
	}))
	mux.Handle("GET /v1/tenants/{tenant}/catalog-sync", authed(a, []string{"tenant"}, func(w http.ResponseWriter, r *http.Request, p auth.Principal) error {
		out, err := c.LastCatalogSync(r.Context(), p, r.PathValue("tenant"))
		if err != nil {
			return err
		}
		w.Header().Set("Content-Type", "application/json")
		_, err = w.Write(out)
		return err
	}))
}
