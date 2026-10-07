// Package oidcauth signs people in through their Tenant's OIDC identity
// provider (#21, #22) and authenticates API requests by session cookie or
// bearer ID token.
//
// Keel runs the authorization-code flow server-side (PKCE + state + nonce);
// tokens never reach the browser. Sessions live in Postgres, keyed by the
// SHA-256 of a random cookie token. Every sign-in, failed sign-in and sign-out
// is an Activity in the identity provider's Tenant.
package oidcauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/jackc/pgx/v5"
	"golang.org/x/oauth2"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/auth"
	"github.com/hx-thanadej/keel/internal/store"
)

const (
	sessionCookie = "keel_session"
	stateCookie   = "keel_login"
)

// Config configures sign-in.
type Config struct {
	BaseURL       string        // Keel's external URL; callback is BaseURL + /auth/callback
	SecureCookies bool          // set Secure on cookies (true behind TLS)
	SessionTTL    time.Duration // default 12h
	CookieKey     []byte        // 32 bytes; encrypts the short-lived login-state cookie
	// Secrets resolves an identity provider's client_secret_ref to the secret.
	Secrets func(ref string) (string, error)
	// HTTPClient talks to identity providers; default http.DefaultClient.
	HTTPClient *http.Client
}

// Service is the sign-in service and request Authenticator.
type Service struct {
	store *store.Store
	cfg   Config
	box   *box

	mu        sync.Mutex
	providers map[string]*oidc.Provider
}

// New returns a sign-in Service.
func New(s *store.Store, cfg Config) (*Service, error) {
	if cfg.BaseURL == "" || cfg.Secrets == nil {
		return nil, errors.New("oidcauth: BaseURL and Secrets are required")
	}
	b, err := newBox(cfg.CookieKey)
	if err != nil {
		return nil, err
	}
	if cfg.SessionTTL == 0 {
		cfg.SessionTTL = 12 * time.Hour
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = http.DefaultClient
	}
	cfg.BaseURL = strings.TrimSuffix(cfg.BaseURL, "/")
	return &Service{store: s, cfg: cfg, box: b, providers: map[string]*oidc.Provider{}}, nil
}

type idp struct {
	ID, TenantID     string
	TenantIsHome     bool
	Issuer, ClientID string
	SecretRef        string
	GroupsClaim      string
	EmailDomain      *string
}

func (s *Service) lookup(ctx context.Context, tenantSlug, issuer *string) (idp, error) {
	var i idp
	err := s.store.AppPool().QueryRow(ctx, `SELECT id::text, tenant_id::text, tenant_is_home, issuer, client_id, client_secret_ref, groups_claim, email_domain FROM idp_lookup($1, $2)`,
		tenantSlug, issuer).Scan(&i.ID, &i.TenantID, &i.TenantIsHome, &i.Issuer, &i.ClientID, &i.SecretRef, &i.GroupsClaim, &i.EmailDomain)
	return i, err
}

func (s *Service) ctx(ctx context.Context) context.Context {
	return oidc.ClientContext(ctx, s.cfg.HTTPClient)
}

func (s *Service) provider(ctx context.Context, issuer string) (*oidc.Provider, error) {
	s.mu.Lock()
	p, ok := s.providers[issuer]
	s.mu.Unlock()
	if ok {
		return p, nil
	}
	p, err := oidc.NewProvider(s.ctx(ctx), issuer)
	if err != nil {
		return nil, fmt.Errorf("discover %s: %w", issuer, err)
	}
	s.mu.Lock()
	s.providers[issuer] = p
	s.mu.Unlock()
	return p, nil
}

func (s *Service) oauth(ctx context.Context, i idp) (*oauth2.Config, *oidc.Provider, error) {
	p, err := s.provider(ctx, i.Issuer)
	if err != nil {
		return nil, nil, err
	}
	secret, err := s.cfg.Secrets(i.SecretRef)
	if err != nil || secret == "" {
		return nil, nil, fmt.Errorf("client secret %q unavailable", i.SecretRef)
	}
	return &oauth2.Config{
		ClientID: i.ClientID, ClientSecret: secret, Endpoint: p.Endpoint(),
		RedirectURL: s.cfg.BaseURL + "/auth/callback",
		Scopes:      []string{oidc.ScopeOpenID, "email", "profile", "groups"},
	}, p, nil
}

type loginState struct {
	State, Nonce, Verifier, Tenant, ReturnTo string
	Expires                                  int64
}

// Mount registers /auth routes.
func (s *Service) Mount(mux interface {
	HandleFunc(string, func(http.ResponseWriter, *http.Request))
}) {
	mux.HandleFunc("GET /auth/login", s.handleLogin)
	mux.HandleFunc("GET /auth/callback", s.handleCallback)
	mux.HandleFunc("POST /auth/logout", s.handleLogout)
	mux.HandleFunc("GET /auth/me", s.handleMe)
}

func (s *Service) handleLogin(w http.ResponseWriter, r *http.Request) {
	slug := r.URL.Query().Get("tenant")
	i, err := s.lookup(r.Context(), &slug, nil)
	if err != nil {
		http.Error(w, "unknown tenant or no identity provider", http.StatusNotFound)
		return
	}
	oc, _, err := s.oauth(r.Context(), i)
	if err != nil {
		http.Error(w, "identity provider unavailable", http.StatusBadGateway)
		return
	}
	st := loginState{State: rand.Text(), Nonce: rand.Text(), Verifier: oauth2.GenerateVerifier(), Tenant: slug,
		ReturnTo: safeReturn(r.URL.Query().Get("return_to")), Expires: time.Now().Add(10 * time.Minute).Unix()}
	sealed, err := s.box.seal(st)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: stateCookie, Value: sealed, Path: "/auth/callback", HttpOnly: true, Secure: s.cfg.SecureCookies, SameSite: http.SameSiteLaxMode, MaxAge: 600})
	http.Redirect(w, r, oc.AuthCodeURL(st.State, oidc.Nonce(st.Nonce), oauth2.S256ChallengeOption(st.Verifier)), http.StatusFound)
}

// safeReturn only allows same-site relative paths, to avoid open redirects.
func safeReturn(p string) string {
	if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || strings.Contains(p, "\\") {
		return "/"
	}
	return p
}

type claims struct {
	Subject       string   `json:"sub"`
	Email         string   `json:"email"`
	EmailVerified *bool    `json:"email_verified"`
	AMR           []string `json:"amr"`
}

func (s *Service) handleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	c, err := r.Cookie(stateCookie)
	var st loginState
	if err != nil || s.box.open(c.Value, &st) != nil || st.Expires < time.Now().Unix() || r.URL.Query().Get("state") != st.State {
		http.Error(w, "login expired or tampered; start again", http.StatusBadRequest)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: stateCookie, Path: "/auth/callback", MaxAge: -1})
	i, err := s.lookup(ctx, &st.Tenant, nil)
	if err != nil {
		http.Error(w, "unknown tenant", http.StatusNotFound)
		return
	}
	oc, prov, err := s.oauth(ctx, i)
	if err != nil {
		http.Error(w, "identity provider unavailable", http.StatusBadGateway)
		return
	}
	tok, err := oc.Exchange(s.ctx(ctx), r.URL.Query().Get("code"), oauth2.VerifierOption(st.Verifier))
	if err != nil {
		s.recordSignIn(ctx, i, "unknown", activity.Failure, "code exchange failed")
		http.Error(w, "sign-in failed", http.StatusForbidden)
		return
	}
	raw, _ := tok.Extra("id_token").(string)
	idt, err := prov.Verifier(&oidc.Config{ClientID: i.ClientID}).Verify(s.ctx(ctx), raw)
	if err != nil || idt.Nonce != st.Nonce {
		s.recordSignIn(ctx, i, "unknown", activity.Failure, "id token invalid")
		http.Error(w, "sign-in failed", http.StatusForbidden)
		return
	}
	p, err := s.principal(ctx, i, idt)
	if err != nil {
		s.recordSignIn(ctx, i, subjectHint(idt), activity.Failure, err.Error())
		http.Error(w, "sign-in refused: "+err.Error(), http.StatusForbidden)
		return
	}
	token := rand.Text() + rand.Text()
	sum := sha256.Sum256([]byte(token))
	err = s.store.InTenant(ctx, i.TenantID, func(tx pgx.Tx) error {
		pj, _ := json.Marshal(p)
		if _, err := tx.Exec(ctx, `INSERT INTO sessions (id_hash, tenant_id, principal, expires_at) VALUES ($1, $2, $3, $4)`,
			sum[:], i.TenantID, pj, time.Now().Add(s.cfg.SessionTTL)); err != nil {
			return err
		}
		_, err := activity.Record(ctx, tx, signInActivity(i, p.Subject, p, activity.Success, "issuer "+i.Issuer))
		return err
	})
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: token, Path: "/", HttpOnly: true, Secure: s.cfg.SecureCookies, SameSite: http.SameSiteLaxMode, MaxAge: int(s.cfg.SessionTTL.Seconds())})
	http.Redirect(w, r, st.ReturnTo, http.StatusFound)
}

func subjectHint(idt *oidc.IDToken) string {
	var c claims
	if idt.Claims(&c) == nil && c.Email != "" {
		return "user:" + c.Email
	}
	return "unknown"
}

// principal maps a verified ID token to a Principal.
func (s *Service) principal(ctx context.Context, i idp, idt *oidc.IDToken) (auth.Principal, error) {
	var c claims
	if err := idt.Claims(&c); err != nil {
		return auth.Principal{}, errors.New("unreadable claims")
	}
	if c.Email == "" || c.EmailVerified == nil || !*c.EmailVerified {
		return auth.Principal{}, errors.New("verified email required")
	}
	if i.EmailDomain != nil && *i.EmailDomain != "" && !strings.HasSuffix(strings.ToLower(c.Email), "@"+strings.ToLower(*i.EmailDomain)) {
		return auth.Principal{}, errors.New("email domain not allowed")
	}
	var all map[string]any
	_ = idt.Claims(&all)
	groups := stringList(all[i.GroupsClaim])
	rows, err := s.store.AppPool().Query(ctx, `SELECT role, target_tenant_id::text, team_ids::text[] FROM idp_bindings($1, $2)`, i.ID, groups)
	if err != nil {
		return auth.Principal{}, err
	}
	bindings, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (auth.Binding, error) {
		var b auth.Binding
		err := r.Scan(&b.Role, &b.TenantID, &b.TeamIDs)
		return b, err
	})
	if err != nil {
		return auth.Principal{}, err
	}
	return auth.Principal{
		Subject: "user:" + strings.ToLower(c.Email), Kind: auth.KindHuman,
		TenantID: i.TenantID, Home: i.TenantIsHome, Issuer: i.Issuer,
		MFA:      slices.ContainsFunc(c.AMR, func(m string) bool { return m == "mfa" || m == "otp" || m == "hwk" || m == "swk" }),
		Bindings: bindings,
	}, nil
}

func stringList(v any) []string {
	var out []string
	switch t := v.(type) {
	case []any:
		for _, x := range t {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
	case string:
		out = append(out, t)
	}
	return out
}

func signInActivity(i idp, subject string, p auth.Principal, outcome activity.Outcome, detail string) activity.Activity {
	typ, op := "keel.session.signed_in", "SignIn"
	if outcome == activity.Failure {
		typ = "keel.session.sign_in_failed"
	}
	return activity.Activity{
		TenantID: i.TenantID, Source: "keel/auth", Type: typ, Subject: "identity_provider/" + i.ID, Operation: op,
		Kind: activity.Other, Actor: activity.Actor{Type: activity.ActorHuman, UID: subject, Session: &activity.Session{Issuer: i.Issuer, MFA: p.MFA}},
		Outcome: outcome, StatusDetail: detail,
	}
}

func (s *Service) recordSignIn(ctx context.Context, i idp, subject string, outcome activity.Outcome, detail string) {
	_ = s.store.InTenant(ctx, i.TenantID, func(tx pgx.Tx) error {
		_, err := activity.Record(ctx, tx, signInActivity(i, subject, auth.Principal{}, outcome, detail))
		return err
	})
}

func (s *Service) handleLogout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	c, err := r.Cookie(sessionCookie)
	if err == nil {
		sum := sha256.Sum256([]byte(c.Value))
		if tenant, p, err := s.session(ctx, sum[:]); err == nil {
			_ = s.store.InTenant(ctx, tenant, func(tx pgx.Tx) error {
				if _, err := tx.Exec(ctx, `UPDATE sessions SET revoked_at = now() WHERE id_hash = $1`, sum[:]); err != nil {
					return err
				}
				_, err := activity.Record(ctx, tx, activity.Activity{TenantID: tenant, Source: "keel/auth", Type: "keel.session.signed_out",
					Operation: "SignOut", Kind: activity.Other, Actor: activity.Actor{Type: activity.ActorHuman, UID: p.Subject}, Outcome: activity.Success})
				return err
			})
		}
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Path: "/", MaxAge: -1, HttpOnly: true, Secure: s.cfg.SecureCookies, SameSite: http.SameSiteLaxMode})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) handleMe(w http.ResponseWriter, r *http.Request) {
	p, err := s.Authenticate(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"unauthenticated"}`))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(p)
}

func (s *Service) session(ctx context.Context, idHash []byte) (string, auth.Principal, error) {
	var tenant string
	var pj []byte
	if err := s.store.AppPool().QueryRow(ctx, `SELECT tenant_id::text, principal FROM session_lookup($1)`, idHash).Scan(&tenant, &pj); err != nil {
		return "", auth.Principal{}, auth.ErrUnauthenticated
	}
	var p auth.Principal
	if err := json.Unmarshal(pj, &p); err != nil {
		return "", auth.Principal{}, err
	}
	return tenant, p, nil
}

// Authenticate implements auth.Authenticator: session cookie, else bearer ID token.
func (s *Service) Authenticate(r *http.Request) (auth.Principal, error) {
	ctx := r.Context()
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return s.bearer(ctx, strings.TrimPrefix(h, "Bearer "))
	}
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return auth.Principal{}, auth.ErrUnauthenticated
	}
	sum := sha256.Sum256([]byte(c.Value))
	_, p, err := s.session(ctx, sum[:])
	return p, err
}

func (s *Service) bearer(ctx context.Context, raw string) (auth.Principal, error) {
	iss, err := unverifiedIssuer(raw)
	if err != nil {
		return auth.Principal{}, auth.ErrUnauthenticated
	}
	i, err := s.lookup(ctx, nil, &iss)
	if err != nil {
		return auth.Principal{}, auth.ErrUnauthenticated
	}
	prov, err := s.provider(ctx, i.Issuer)
	if err != nil {
		return auth.Principal{}, auth.ErrUnauthenticated
	}
	idt, err := prov.Verifier(&oidc.Config{ClientID: i.ClientID}).Verify(s.ctx(ctx), raw)
	if err != nil {
		return auth.Principal{}, auth.ErrUnauthenticated
	}
	p, err := s.principal(ctx, i, idt)
	if err != nil {
		return auth.Principal{}, auth.ErrUnauthenticated
	}
	return p, nil
}

// unverifiedIssuer reads iss to choose which provider verifies the token.
// The signature is checked afterwards against that provider's keys.
func unverifiedIssuer(raw string) (string, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return "", errors.New("not a JWT")
	}
	payload, err := decodeSegment(parts[1])
	if err != nil {
		return "", err
	}
	var c struct {
		Iss string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &c); err != nil || c.Iss == "" {
		return "", errors.New("no issuer")
	}
	return c.Iss, nil
}
