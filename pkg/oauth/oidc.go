// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package oauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/hashicorp/vault-mcp-server/pkg/client"
)

// oidcPending holds the round-trip state for an in-flight OIDC login, keyed by
// the Vault-generated `state` parameter that appears in the IdP callback URL.
// Entries are deleted on first use or when they expire.
type oidcPending struct {
	SealedAuthState string
	ClientNonce     string
	ExpiresAt       time.Time
}

// oidcStateMap stores {vault_state → oidcPending}. It is shared between the
// main server (port 8080, /vault/oidc/start) and the callback listener (port
// 8250, /oidc/callback) which run in the same process.
var oidcStateMap sync.Map

// oidcStart initiates the Vault OIDC login.
//
// It calls Vault's auth_url endpoint using the pre-registered callback URI
// (http://localhost:8250/oidc/callback — the Vault CLI default, always allowed).
// The Vault-generated `state` param is parsed from the returned URL and stored
// in oidcStateMap so the port-8250 callback can resume the OAuth flow without
// any server-side session or cookies crossing ports.
func (r *Router) oidcStart(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if err := req.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	encState := req.FormValue("auth_state")

	var st AuthState
	if _, err := r.tokenSvc.Parse(string(TokenTypeAuthState), encState, &st); err != nil {
		http.Error(w, "invalid or expired auth_state", http.StatusBadRequest)
		return
	}

	clientNonce, err := randomNonce()
	if err != nil {
		http.Error(w, "failed to start oidc", http.StatusInternalServerError)
		return
	}

	// Use the pre-registered callback URI so no Vault admin changes are needed.
	// When OIDCCallbackPort == 0, fall back to the main server's callback route
	// (requires admin registration of that URI in the Vault OIDC role).
	callback := r.cfg.OIDCCallbackURL(r.cfg.BaseURL(req))

	ctx, cancel := context.WithTimeout(req.Context(), 20*time.Second)
	defer cancel()

	authURL, err := client.OIDCAuthURL(ctx, r.vaultAuthParams(), r.cfg.OIDCMount, r.cfg.OIDCRole, callback, clientNonce)
	if err != nil {
		r.logger.WithError(err).Warn("vault oidc auth_url failed")
		r.renderLogin(w, req, encState, "OIDC start failed: "+truncateErr(err))
		return
	}

	// Parse Vault's generated `state` parameter out of the IdP URL so we can
	// look it up when the browser returns to the callback.
	u, err := url.Parse(authURL)
	if err != nil || u.Query().Get("state") == "" {
		r.logger.WithError(err).Warn("vault oidc auth_url missing state param")
		r.renderLogin(w, req, encState, "OIDC start failed: no state in auth_url")
		return
	}
	vaultState := u.Query().Get("state")

	oidcStateMap.Store(vaultState, oidcPending{
		SealedAuthState: encState,
		ClientNonce:     clientNonce,
		ExpiresAt:       time.Now().Add(r.cfg.AuthCodeTTL),
	})

	http.Redirect(w, req, authURL, http.StatusFound)
}

// oidcCallback completes the OIDC flow. It is mounted on the port-8250 server
// at /oidc/callback (matching the Vault CLI's pre-registered redirect URI) as
// well as on the main server at /vault/oidc/callback as a fallback for
// deployments where the admin has registered that URI instead.
func (r *Router) oidcCallback(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	q := req.URL.Query()
	vaultState := q.Get("state")
	code := q.Get("code")
	oidcErr := q.Get("error")

	// IdP returned an error (e.g. access_denied from bad credentials).
	// Recover the pending state so we can redirect back to the login page with
	// a human-readable error message rendered in the same styled UI.
	if oidcErr != "" {
		errDesc := q.Get("error_description")
		if errDesc == "" {
			errDesc = oidcErr
		}
		friendlyMsg := "OIDC sign-in failed: " + errDesc

		if vaultState != "" {
			if v, ok := oidcStateMap.LoadAndDelete(vaultState); ok {
				pending := v.(oidcPending)
				if !time.Now().After(pending.ExpiresAt) {
					serverURL := r.cfg.ServerURL
					if serverURL == "" {
						serverURL = r.cfg.BaseURL(req)
					}
					loginURL := serverURL + "/vault/login?auth_state=" +
						url.QueryEscape(pending.SealedAuthState) + "&error=" +
						url.QueryEscape(friendlyMsg)
					http.Redirect(w, req, loginURL, http.StatusFound)
					return
				}
			}
		}

		// Pending state not found or expired — render a standalone error card.
		r.renderCallbackError(w, friendlyMsg)
		return
	}

	if vaultState == "" || code == "" {
		r.renderCallbackError(w, "missing state or code in callback — please restart the login")
		return
	}

	// Retrieve and consume the pending state (one-shot).
	v, ok := oidcStateMap.LoadAndDelete(vaultState)
	if !ok {
		http.Error(w, "unknown or expired oidc session — please restart the login", http.StatusBadRequest)
		return
	}
	pending := v.(oidcPending)
	if time.Now().After(pending.ExpiresAt) {
		http.Error(w, "oidc session expired — please restart the login", http.StatusBadRequest)
		return
	}

	var st AuthState
	if _, err := r.tokenSvc.Parse(string(TokenTypeAuthState), pending.SealedAuthState, &st); err != nil {
		http.Error(w, "invalid or expired auth_state", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(req.Context(), 20*time.Second)
	defer cancel()

	vaultToken, err := client.OIDCCallback(ctx, r.vaultAuthParams(), r.cfg.OIDCMount, vaultState, code, pending.ClientNonce)
	if err != nil {
		r.logger.WithError(err).Warn("vault oidc callback failed")
		// Can't render the login page from the callback port — redirect to it.
		loginURL := r.cfg.BaseURL(req) + "/vault/login?auth_state=" +
			url.QueryEscape(pending.SealedAuthState) + "&error=" +
			url.QueryEscape("OIDC sign-in failed: "+truncateErr(err))
		// BaseURL from port 8250 would be wrong; use the configured server URL.
		if r.cfg.ServerURL != "" {
			loginURL = r.cfg.ServerURL + "/vault/login?auth_state=" +
				url.QueryEscape(pending.SealedAuthState) + "&error=" +
				url.QueryEscape("OIDC sign-in failed: "+truncateErr(err))
		}
		http.Redirect(w, req, loginURL, http.StatusFound)
		return
	}

	r.issueAuthCodeAndRedirect(w, req, st, vaultToken)
}

// OIDCCallbackMux returns an http.ServeMux with only the /oidc/callback route
// registered. Mount this on a separate net/http.Server on OIDCCallbackPort so
// the browser's redirect to http://localhost:8250/oidc/callback is handled
// without requiring Vault admin registration of the main server's callback URL.
func (r *Router) OIDCCallbackMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/oidc/callback", r.oidcCallback)
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","service":"vault-oidc-callback"}`))
	})
	return mux
}

func randomNonce() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
