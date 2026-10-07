// Package api is Keel's HTTP surface.
package api

import (
	"encoding/json"
	"net/http"

	"github.com/hx-thanadej/keel/internal/auth"
	"github.com/hx-thanadej/keel/internal/catalog"
	"github.com/hx-thanadej/keel/internal/discovery"
)

// Info is build metadata exposed on /healthz.
type Info struct {
	Version string
}

// Deps are the services the API serves. Nil services are not mounted.
type Deps struct {
	Auth     auth.Authenticator
	Sessions Mounter // sign-in routes under /auth
	Catalog  *catalog.Service
	// Discovery sources by provider name, e.g. "tencent".
	Discovery map[string]discovery.Source
	Cost      *CostDeps
	Budgets   *BudgetDeps
	// Authz enables the Findings inbox (shared by cost, rightsizing, security).
	Authz     catalog.Authorizer
	Rightsize *RightsizeDeps
	Flows     *FlowDeps
	Vending   *VendingDeps
	Promotion *PromotionDeps
	Templates *TemplateDeps
	Registry  *RegistryDeps
	Exception *ExceptionDeps
	Scans     *ScanDeps
	Attest    *AttestDeps
	Admission *AdmissionDeps
	SBOM      *SBOMDeps
	VEX       *VEXDeps
	Controls  *ControlDeps
}

// Mounter registers its own routes. The parameter is an unnamed interface so
// implementers need not import this package.
type Mounter interface {
	Mount(interface {
		HandleFunc(string, func(http.ResponseWriter, *http.Request))
	})
}

// Router is the Keel API handler. It remembers every pattern it serves so the
// cross-Tenant isolation suite can prove it covers them all.
type Router struct {
	h        http.Handler
	patterns []string
}

// ServeHTTP implements http.Handler.
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) { r.h.ServeHTTP(w, req) }

// Patterns lists every registered route pattern, e.g. "GET /v1/tenants/{tenant}".
func (r *Router) Patterns() []string { return r.patterns }

type recordingMux struct {
	*http.ServeMux
	patterns *[]string
}

func (m recordingMux) Handle(pattern string, h http.Handler) {
	*m.patterns = append(*m.patterns, pattern)
	m.ServeMux.Handle(pattern, h)
}

func (m recordingMux) HandleFunc(pattern string, h func(http.ResponseWriter, *http.Request)) {
	m.Handle(pattern, http.HandlerFunc(h))
}

// Mux is what route-registering code receives.
type Mux interface {
	Handle(pattern string, h http.Handler)
	HandleFunc(pattern string, h func(http.ResponseWriter, *http.Request))
}

// NewRouter returns the Keel API handler.
func NewRouter(info Info, deps Deps) *Router {
	r := &Router{}
	mux := recordingMux{ServeMux: http.NewServeMux(), patterns: &r.patterns}
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "version": info.Version})
	})
	if deps.Sessions != nil {
		deps.Sessions.Mount(mux)
	}
	if deps.Catalog != nil && deps.Auth != nil {
		mountCatalog(mux, deps.Catalog, deps.Auth)
		mountDiscovery(mux, deps.Catalog, deps.Auth, deps.Discovery)
		if deps.Cost != nil {
			mountCost(mux, deps.Auth, *deps.Cost)
		}
		if deps.Budgets != nil {
			mountBudgets(mux, deps.Auth, *deps.Budgets)
		}
		if deps.Authz != nil {
			mountFindings(mux, deps.Auth, deps.Catalog, deps.Authz)
		}
		if deps.Rightsize != nil {
			mountRightsize(mux, deps.Auth, *deps.Rightsize)
		}
		if deps.Flows != nil {
			mountFlows(mux, deps.Auth, *deps.Flows)
		}
		if deps.Vending != nil {
			mountVending(mux, deps.Auth, *deps.Vending)
		}
		if deps.Promotion != nil {
			mountPromotions(mux, deps.Auth, *deps.Promotion)
		}
		if deps.Templates != nil {
			mountTemplates(mux, deps.Auth, *deps.Templates)
		}
		if deps.Registry != nil {
			mountRegistry(mux, deps.Auth, *deps.Registry)
		}
		if deps.Exception != nil {
			mountExceptions(mux, deps.Auth, *deps.Exception)
		}
		if deps.Scans != nil {
			mountScans(mux, deps.Auth, *deps.Scans)
		}
		if deps.Attest != nil {
			mountAttest(mux, deps.Auth, *deps.Attest)
		}
		if deps.Admission != nil {
			mountAdmission(mux, deps.Auth, *deps.Admission)
		}
		if deps.SBOM != nil {
			mountSBOM(mux, deps.Auth, *deps.SBOM)
		}
		if deps.VEX != nil {
			mountVEX(mux, deps.Auth, *deps.VEX)
		}
		if deps.Controls != nil {
			mountControls(mux, deps.Auth, *deps.Controls)
		}
	}
	// Session cookies make cross-site writes possible; reject them (CSRF).
	r.h = http.NewCrossOriginProtection().Handler(mux.ServeMux)
	return r
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
