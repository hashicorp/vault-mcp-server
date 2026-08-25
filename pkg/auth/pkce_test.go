// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// freeTCPPort asks the OS for an available TCP port by briefly binding to :0.
func freeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

// redirectToListenerWithState simulates the IdP redirect arriving at the local
// callback listener. state is echoed back as the "state" query parameter —
// pass the empty string to omit it (e.g. for IdP-error tests where the handler
// returns before checking state). When state is the empty string and code is
// non-empty the helper probes the listener for the state by issuing a dummy
// request first — use redirectToListenerAutoState for that.
func redirectToListenerWithState(t *testing.T, listenerAddr, callbackPath, code, idpError, errorDesc, state string) {
	t.Helper()
	q := url.Values{}
	if idpError != "" {
		q.Set("error", idpError)
		q.Set("error_description", errorDesc)
	} else {
		q.Set("code", code)
		if state != "" {
			q.Set("state", state)
		}
	}
	targetURL := fmt.Sprintf("http://%s%s?%s", listenerAddr, callbackPath, q.Encode())
	resp, err := http.Get(targetURL) //nolint:noctx // test helper
	if err != nil {
		return // listener may have already shut down — that's fine
	}
	resp.Body.Close()
}

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
func TestRunSinglePKCEFlow_SuccessfulRedirect(t *testing.T) {
	const fixedState = "test-state-value"
	orig := stateGenerator
	stateGenerator = func() (string, error) { return fixedState, nil }
	t.Cleanup(func() { stateGenerator = orig })

	tokenSrv := newFakeTokenServer(t, "subject-access-token", 0)
	port := freeTCPPort(t)
	listenerAddr := fmt.Sprintf("127.0.0.1:%d", port)

	cfg := PKCEConfig{
		ClientID:    "test-client",
		AuthURL:     "http://idp.example.com/auth",
		TokenURL:    tokenSrv.URL,
		RedirectURL: fmt.Sprintf("http://%s/callback", listenerAddr),
		Scopes:      []string{"openid"},
		Deadline:    5 * time.Second,
	}

	// Deliver the redirect after the listener is up, echoing the known state back.
	go func() {
		time.Sleep(50 * time.Millisecond)
		redirectToListenerWithState(t, listenerAddr, "/callback", "auth-code-abc", "", "", fixedState)
	}()

	token, err := runSinglePKCEFlow(context.Background(), cfg, "Subject")
	require.NoError(t, err)
	assert.Equal(t, "subject-access-token", token)
}

// TestRunSinglePKCEFlow_Timeout: no redirect arrives → ErrAuthTimeout, listener shuts down.
func TestRunSinglePKCEFlow_Timeout(t *testing.T) {
	tokenSrv := newFakeTokenServer(t, "unused", 0)
	port := freeTCPPort(t)

	cfg := PKCEConfig{
		ClientID:    "test-client",
		AuthURL:     "http://idp.example.com/auth",
		TokenURL:    tokenSrv.URL,
		RedirectURL: fmt.Sprintf("http://127.0.0.1:%d/callback", port),
		Deadline:    100 * time.Millisecond, // intentionally short
	}

	// No redirect sent — flow must time out.
	token, err := runSinglePKCEFlow(context.Background(), cfg, "Subject")
	assert.Empty(t, token)
	assert.True(t, errors.Is(err, ErrAuthTimeout),
		"expected ErrAuthTimeout, got: %v", err)
}

// TestRunSinglePKCEFlow_IdPError: redirect arrives with error param → IdP error returned.
func TestRunSinglePKCEFlow_IdPError(t *testing.T) {
	tokenSrv := newFakeTokenServer(t, "unused", 0)
	port := freeTCPPort(t)
	listenerAddr := fmt.Sprintf("127.0.0.1:%d", port)

	cfg := PKCEConfig{
		ClientID:    "test-client",
		AuthURL:     "http://idp.example.com/auth",
		TokenURL:    tokenSrv.URL,
		RedirectURL: fmt.Sprintf("http://%s/callback", listenerAddr),
		Deadline:    5 * time.Second,
	}

	go func() {
		time.Sleep(50 * time.Millisecond)
		redirectToListenerWithState(t, listenerAddr, "/callback", "", "access_denied", "User denied the request", "")
	}()

	token, err := runSinglePKCEFlow(context.Background(), cfg, "Subject")
	assert.Empty(t, token)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "access_denied")
	assert.Contains(t, err.Error(), "User denied the request")
}

// TestExchangeCode_NonOKStatus: token endpoint returns non-2xx → error with HTTP status.
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
	assert.Equal(t, "tok", token)

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
	assert.Equal(t, "tok", token)

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
