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

// redirectToListener simulates the IdP redirect arriving at the local callback listener.
// It fires a GET to the callback path with either a code or an error param.
func redirectToListener(t *testing.T, listenerAddr, callbackPath, code, idpError, errorDesc string) {
	t.Helper()
	q := url.Values{}
	if idpError != "" {
		q.Set("error", idpError)
		q.Set("error_description", errorDesc)
	} else {
		q.Set("code", code)
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
func newFakeTokenServer(t *testing.T, successToken string, statusCode int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
func TestRunSinglePKCEFlow_SuccessfulRedirect(t *testing.T) {
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

	// Deliver the redirect after the listener is up.
	go func() {
		time.Sleep(50 * time.Millisecond)
		redirectToListener(t, listenerAddr, "/callback", "auth-code-abc", "", "")
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
		redirectToListener(t, listenerAddr, "/callback", "", "access_denied", "User denied the request")
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
	token, err := exchangeCode(cfg, "some-code", "some-verifier")
	assert.Empty(t, token)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "500")
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
	authURL := buildAuthURL(cfg, "test-challenge")
	parsed, err := url.Parse(authURL)
	require.NoError(t, err)
	q := parsed.Query()
	assert.Equal(t, "code", q.Get("response_type"))
	assert.Equal(t, "my-client", q.Get("client_id"))
	assert.Equal(t, "http://localhost:9000/callback", q.Get("redirect_uri"))
	assert.Equal(t, "test-challenge", q.Get("code_challenge"))
	assert.Equal(t, "S256", q.Get("code_challenge_method"))
	assert.Equal(t, "openid profile", q.Get("scope"))
}
