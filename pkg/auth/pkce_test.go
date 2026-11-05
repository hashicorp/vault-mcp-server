// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newFakeTokenServer returns an httptest.Server that mimics an OAuth token endpoint.
// When statusCode != 0 and != 200 it returns that code with an error JSON body.
// Otherwise it returns successToken as access_token.
// captureReq, if non-nil, receives the parsed request body and Authorization
// header so callers can assert on the auth method used.
type capturedTokenRequest struct {
	AuthHeader string
	Body       url.Values
}

func newFakeTokenServer(t *testing.T, successToken string, statusCode int) *httptest.Server {
	t.Helper()
	return newFakeTokenServerCapture(t, successToken, statusCode, nil)
}

func newFakeTokenServerCapture(t *testing.T, successToken string, statusCode int, capture *capturedTokenRequest) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if capture != nil {
			capture.AuthHeader = r.Header.Get("Authorization")
			_ = r.ParseForm()
			capture.Body = r.PostForm
		}
		if statusCode != 0 && statusCode != http.StatusOK {
			w.WriteHeader(statusCode)
			fmt.Fprintf(w, `{"error":"server_error"}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]string{"access_token": successToken}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestRunSinglePKCEFlow_SuccessfulRedirect: happy path — code arrives → token returned.
// A fixed stateGenerator is injected so the redirect can echo back the known state.
func TestExchangeCode_NonOKStatus(t *testing.T) {
	srv := newFakeTokenServer(t, "", http.StatusInternalServerError)

	cfg := PKCEConfig{
		ClientID:    "test-client",
		TokenURL:    srv.URL,
		RedirectURL: "http://127.0.0.1:49999/callback",
	}
	token, err := exchangeCode(cfg, "some-code", "some-verifier", "unused-state")
	assert.Empty(t, token)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "500")
}

// TestExchangeCode_ClientSecretBasic: when ClientSecret is set, credentials go
// in the Authorization header (client_secret_basic) and NOT in the body.
func TestExchangeCode_ClientSecretBasic(t *testing.T) {
	var cap capturedTokenRequest
	srv := newFakeTokenServerCapture(t, "tok", 0, &cap)

	cfg := PKCEConfig{
		ClientID:     "my-client",
		ClientSecret: "my-secret",
		TokenURL:     srv.URL,
		RedirectURL:  "http://127.0.0.1:49999/callback",
	}
	token, err := exchangeCode(cfg, "code-xyz", "verifier-abc", "state-123")
	require.NoError(t, err)
	assert.Equal(t, "tok", token.AccessToken)

	// Basic auth header must be present.
	assert.True(t, strings.HasPrefix(cap.AuthHeader, "Basic "),
		"expected Basic auth header, got: %q", cap.AuthHeader)

	// client_id and client_secret must NOT appear in the POST body.
	assert.Empty(t, cap.Body.Get("client_id"), "client_id must not be in body when using client_secret_basic")
	assert.Empty(t, cap.Body.Get("client_secret"), "client_secret must never be in body")
}

// TestExchangeCode_PublicClient: when ClientSecret is empty, client_id goes in
// the body and no Authorization header is set.
func TestExchangeCode_PublicClient(t *testing.T) {
	var cap capturedTokenRequest
	srv := newFakeTokenServerCapture(t, "tok", 0, &cap)

	cfg := PKCEConfig{
		ClientID:    "public-client",
		TokenURL:    srv.URL,
		RedirectURL: "http://127.0.0.1:49999/callback",
	}
	token, err := exchangeCode(cfg, "code-xyz", "verifier-abc", "state-123")
	require.NoError(t, err)
	assert.Equal(t, "tok", token.AccessToken)

	assert.Empty(t, cap.AuthHeader, "no Authorization header for public client")
	assert.Equal(t, "public-client", cap.Body.Get("client_id"))
}

// TestCodeChallenge: S256 challenge is unpadded base64url.
func TestCodeChallenge(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := codeChallenge(verifier)
	assert.NotEmpty(t, challenge)
	assert.False(t, strings.Contains(challenge, "="), "challenge must be unpadded base64url")
}

// TestGenerateCodeVerifier: produces 43-char unpadded base64url and is random.
func TestGenerateCodeVerifier(t *testing.T) {
	v1, err := generateCodeVerifier()
	require.NoError(t, err)
	v2, err := generateCodeVerifier()
	require.NoError(t, err)
	// 32 bytes → ceil(32*8/6) = 43 base64url chars (no padding).
	assert.Equal(t, 43, len(v1))
	assert.NotEqual(t, v1, v2, "two verifiers must differ (crypto random)")
	assert.False(t, strings.Contains(v1, "="), "verifier must be unpadded base64url")
}

// TestBuildAuthURL: authorization URL contains all required PKCE parameters.
func TestBuildAuthURL(t *testing.T) {
	cfg := PKCEConfig{
		ClientID:    "my-client",
		AuthURL:     "https://idp.example.com/oauth/authorize",
		RedirectURL: "http://localhost:9000/callback",
		Scopes:      []string{"openid", "profile"},
	}
	authURL := buildAuthURL(cfg, "test-challenge", "test-state")
	parsed, err := url.Parse(authURL)
	require.NoError(t, err)
	q := parsed.Query()
	assert.Equal(t, "code", q.Get("response_type"))
	assert.Equal(t, "query", q.Get("response_mode"))
	assert.Equal(t, "my-client", q.Get("client_id"))
	assert.Equal(t, "http://localhost:9000/callback", q.Get("redirect_uri"))
	assert.Equal(t, "test-challenge", q.Get("code_challenge"))
	assert.Equal(t, "S256", q.Get("code_challenge_method"))
	assert.Equal(t, "openid profile", q.Get("scope"))
	assert.Equal(t, "test-state", q.Get("state"))

	// Regression guard: redirect_uri must appear percent-encoded — IBM Verify
	// accepts the standard encoded form (url.Values.Encode) and that is what
	// other compliant OAuth clients (e.g. oauth2c) also send.
	assert.Contains(t, authURL, "redirect_uri=http%3A%2F%2Flocalhost%3A9000%2Fcallback",
		"redirect_uri must be percent-encoded in the authorization URL")
}
