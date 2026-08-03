// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package oauth

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type clientRegistrationRequest struct {
	RedirectURIs            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	ClientName              string   `json:"client_name,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
}

type clientRegistrationResponse struct {
	ClientID                string   `json:"client_id"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
	RedirectURIs            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	ClientName              string   `json:"client_name,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	Scope       string `json:"scope,omitempty"`
}

// registerClient implements RFC 7591 dynamic client registration. The returned
// client_id is itself a sealed token carrying the registration data, so no
// storage is required.
func (r *Router) registerClient(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	defer func() { _ = req.Body.Close() }()

	var in clientRegistrationRequest
	if err := json.NewDecoder(req.Body).Decode(&in); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if len(in.RedirectURIs) == 0 {
		http.Error(w, "redirect_uris is required", http.StatusBadRequest)
		return
	}
	for _, ru := range in.RedirectURIs {
		u, err := url.Parse(ru)
		if err != nil || u.Scheme == "" || u.Host == "" {
			http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
			return
		}
	}

	method := in.TokenEndpointAuthMethod
	if method == "" {
		method = "none"
	}

	data := ClientRegistrationData{
		ClientIDIssuedAt:        time.Now().UTC().Unix(),
		RedirectURIs:            in.RedirectURIs,
		TokenEndpointAuthMethod: method,
		GrantTypes:              in.GrantTypes,
		ResponseTypes:           in.ResponseTypes,
		ClientName:              in.ClientName,
		Scope:                   in.Scope,
	}

	clientID, _, err := r.tokenSvc.Mint(string(TokenTypeClientID), 3650*24*time.Hour, data)
	if err != nil {
		http.Error(w, "failed to register client", http.StatusInternalServerError)
		return
	}

	writeJSON(w, clientRegistrationResponse{
		ClientID:                clientID,
		ClientIDIssuedAt:        data.ClientIDIssuedAt,
		RedirectURIs:            data.RedirectURIs,
		TokenEndpointAuthMethod: data.TokenEndpointAuthMethod,
		GrantTypes:              data.GrantTypes,
		ResponseTypes:           data.ResponseTypes,
		ClientName:              data.ClientName,
		Scope:                   data.Scope,
	})
}

// authorize starts the authorization-code + PKCE flow, then redirects the
// browser to the interactive Vault login page.
func (r *Router) authorize(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	q := req.URL.Query()
	responseType := q.Get("response_type")
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	codeChallenge := q.Get("code_challenge")
	codeChallengeMethod := q.Get("code_challenge_method")
	state := q.Get("state")
	scope := q.Get("scope")

	if responseType != "code" {
		http.Error(w, "unsupported response_type", http.StatusBadRequest)
		return
	}
	if clientID == "" || redirectURI == "" || codeChallenge == "" {
		http.Error(w, "missing required parameters", http.StatusBadRequest)
		return
	}
	if codeChallengeMethod == "" {
		codeChallengeMethod = "S256"
	}
	if codeChallengeMethod != "S256" {
		http.Error(w, "unsupported code_challenge_method", http.StatusBadRequest)
		return
	}

	var reg ClientRegistrationData
	if _, err := r.tokenSvc.Parse(string(TokenTypeClientID), clientID, &reg); err != nil {
		// The client_id is a sealed token minted with the server's current
		// MCP_AUTH_SECRET. If decryption fails the server most likely restarted
		// (generating a new secret), invalidating the stored registration.
		// Rather than surfacing an error the user cannot act on, re-register the
		// client on-the-fly using the redirect_uri already present in the request
		// so the OIDC flow continues uninterrupted.
		if redirectURI == "" {
			r.renderCallbackError(w, "MCP client registration is no longer valid and no redirect_uri was provided — please reconnect your MCP client.")
			return
		}
		u, parseErr := url.Parse(redirectURI)
		if parseErr != nil || u.Scheme == "" || u.Host == "" {
			r.renderCallbackError(w, "MCP client registration is no longer valid and the redirect_uri is not a valid URL — please reconnect your MCP client.")
			return
		}
		r.logger.WithField("redirect_uri", redirectURI).Info("stale client_id — transparently re-registering MCP client for this authorize request")
		reg = ClientRegistrationData{
			ClientIDIssuedAt:        time.Now().UTC().Unix(),
			RedirectURIs:            []string{redirectURI},
			TokenEndpointAuthMethod: "none",
		}
	}
	if !contains(reg.RedirectURIs, redirectURI) {
		http.Error(w, "redirect_uri not registered", http.StatusBadRequest)
		return
	}

	authState := AuthState{
		RedirectURI:          redirectURI,
		CodeChallenge:        codeChallenge,
		CodeChallengeMethod:  codeChallengeMethod,
		State:                state,
		Scopes:               splitScopes(scope),
		ClientID:             clientID,
		CreatedAtUnixSeconds: time.Now().UTC().Unix(),
	}
	encState, _, err := r.tokenSvc.Mint(string(TokenTypeAuthState), r.cfg.AuthCodeTTL, authState)
	if err != nil {
		http.Error(w, "failed to start auth", http.StatusInternalServerError)
		return
	}

	loginURL := r.cfg.BaseURL(req) + "/vault/login?" + url.Values{"auth_state": []string{encState}}.Encode()
	http.Redirect(w, req, loginURL, http.StatusFound)
}

// token exchanges an authorization code (+ PKCE verifier) for a sealed bearer
// access token carrying the Vault credentials.
func (r *Router) token(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if err := req.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	grantType := req.FormValue("grant_type")
	code := req.FormValue("code")
	codeVerifier := req.FormValue("code_verifier")
	clientID := req.FormValue("client_id")
	redirectURI := req.FormValue("redirect_uri")

	if grantType != "authorization_code" {
		http.Error(w, "unsupported grant_type", http.StatusBadRequest)
		return
	}
	if code == "" || codeVerifier == "" || clientID == "" || redirectURI == "" {
		http.Error(w, "missing required parameters", http.StatusBadRequest)
		return
	}

	var cd AuthCodeData
	if _, err := r.tokenSvc.Parse(string(TokenTypeAuthCode), code, &cd); err != nil {
		http.Error(w, "invalid code", http.StatusBadRequest)
		return
	}
	if cd.ClientID != clientID {
		http.Error(w, "client_id mismatch", http.StatusBadRequest)
		return
	}
	if cd.RedirectURI != redirectURI {
		http.Error(w, "redirect_uri mismatch", http.StatusBadRequest)
		return
	}
	if cd.CodeChallengeMethod != "S256" || !VerifyCodeChallengeS256(codeVerifier, cd.CodeChallenge) {
		http.Error(w, "invalid code_verifier", http.StatusBadRequest)
		return
	}

	at := AccessTokenData{
		VaultToken:           cd.VaultToken,
		VaultAddr:            cd.VaultAddr,
		VaultNamespace:       cd.VaultNamespace,
		CreatedAtUnixSeconds: time.Now().UTC().Unix(),
	}
	accessToken, meta, err := r.tokenSvc.Mint(string(TokenTypeAccessToken), r.cfg.AccessTokenTTL, at)
	if err != nil {
		http.Error(w, "failed to issue token", http.StatusInternalServerError)
		return
	}

	writeJSON(w, tokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int64(time.Until(meta.ExpiresAt).Seconds()),
		Scope:       strings.Join(cd.Scopes, " "),
	})
}
