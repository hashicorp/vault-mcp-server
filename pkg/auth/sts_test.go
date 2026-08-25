// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package auth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildDelegationJWT constructs a minimal unsigned JWT whose payload contains
// the given claims, for use as a fake STS response body.
func buildDelegationJWT(t *testing.T, sub, actSub string, exp int64) string {
	t.Helper()
	payload := map[string]interface{}{
		"sub": sub,
		"act": map[string]string{"sub": actSub},
		"exp": exp,
	}
	b, err := json.Marshal(payload)
	require.NoError(t, err)
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payloadEnc := base64.RawURLEncoding.EncodeToString(b)
	return fmt.Sprintf("%s.%s.fakesig", header, payloadEnc)
}

// newSTSServer returns an httptest.Server simulating the STS token endpoint.
func newSTSServer(t *testing.T, jwtToken string, statusCode int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if statusCode != 0 && statusCode != http.StatusOK {
			w.WriteHeader(statusCode)
			fmt.Fprintf(w, `{"error":"invalid_request","error_description":"forced failure"}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":%q,"token_type":"urn:ietf:params:oauth:token-type:jwt"}`, jwtToken)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestExchangeTokens_ValidTokens: STS returns a valid JWT → ExchangeTokens returns a
// populated DelegationJWT with correct Sub, Act, Exp, and Raw set to the JWT string.
func TestExchangeTokens_ValidTokens(t *testing.T) {
	futureExp := time.Now().Add(1 * time.Hour).Unix()
	jwtStr := buildDelegationJWT(t, "user@example.com", "mcp-server", futureExp)

	srv := newSTSServer(t, jwtStr, 0)

	result, err := ExchangeTokens("subject-tok", "actor-tok", srv.URL, "ibm-client", "")
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "user@example.com", result.Sub)
	assert.Equal(t, "mcp-server", result.Act.Sub)
	assert.Equal(t, time.Unix(futureExp, 0), result.Exp)
	assert.Equal(t, jwtStr, result.Raw)
}

// TestExchangeTokens_NonOKStatus: STS returns non-2xx → error containing HTTP status.
func TestExchangeTokens_NonOKStatus(t *testing.T) {
	srv := newSTSServer(t, "", http.StatusBadRequest)

	result, err := ExchangeTokens("subject-tok", "actor-tok", srv.URL, "ibm-client", "")
	assert.Nil(t, result)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "400")
}

// TestExchangeTokens_ExpiredJWT: STS returns a JWT with expired exp →
// ExchangeTokens returns ErrTokenExpired (propagated from ParseUnsigned).
func TestExchangeTokens_ExpiredJWT(t *testing.T) {
	pastExp := time.Now().Add(-1 * time.Hour).Unix()
	jwtStr := buildDelegationJWT(t, "user@example.com", "mcp-server", pastExp)

	srv := newSTSServer(t, jwtStr, 0)

	result, err := ExchangeTokens("subject-tok", "actor-tok", srv.URL, "ibm-client", "")
	assert.Nil(t, result)
	assert.True(t, errors.Is(err, ErrTokenExpired),
		"expected ErrTokenExpired, got: %v", err)
}

// TestExchangeTokens_STSErrorBody: STS returns 200 with an error JSON body →
// ExchangeTokens returns a descriptive error.
func TestExchangeTokens_STSErrorBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"error":"invalid_grant","error_description":"token expired"}`)
	}))
	t.Cleanup(srv.Close)

	result, err := ExchangeTokens("subject-tok", "actor-tok", srv.URL, "ibm-client", "")
	assert.Nil(t, result)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid_grant")
}

// TestExchangeTokens_EmptyAccessToken: STS returns 200 with no access_token →
// ExchangeTokens returns a descriptive error.
func TestExchangeTokens_EmptyAccessToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"token_type":"bearer"}`)
	}))
	t.Cleanup(srv.Close)

	result, err := ExchangeTokens("subject-tok", "actor-tok", srv.URL, "ibm-client", "")
	assert.Nil(t, result)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "access_token")
}

// TestExchangeTokens_RequestBody_PublicClient: verifies RFC 8693 fields plus client_id
// in the POST body when no client secret is provided (public client).
func TestExchangeTokens_RequestBody_PublicClient(t *testing.T) {
	futureExp := time.Now().Add(1 * time.Hour).Unix()
	jwtStr := buildDelegationJWT(t, "user@example.com", "mcp-server", futureExp)

	var capturedBody map[string][]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		capturedBody = map[string][]string(r.PostForm)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":%q}`, jwtStr)
	}))
	t.Cleanup(srv.Close)

	_, err := ExchangeTokens("my-subject-tok", "my-actor-tok", srv.URL, "ibm-client-id", "")
	require.NoError(t, err)

	assert.Equal(t, []string{grantTypeTokenExchange}, capturedBody["grant_type"])
	assert.Equal(t, []string{"my-subject-tok"}, capturedBody["subject_token"])
	assert.Equal(t, []string{tokenTypeAccessToken}, capturedBody["subject_token_type"])
	assert.Equal(t, []string{"my-actor-tok"}, capturedBody["actor_token"])
	assert.Equal(t, []string{tokenTypeAccessToken}, capturedBody["actor_token_type"])
	assert.Equal(t, []string{"ibm-client-id"}, capturedBody["client_id"])
}

// TestExchangeTokens_RequestBody_ConfidentialClient: verifies that when a client secret
// is provided, credentials are sent via HTTP Basic auth and client_id is NOT in the body.
func TestExchangeTokens_RequestBody_ConfidentialClient(t *testing.T) {
	futureExp := time.Now().Add(1 * time.Hour).Unix()
	jwtStr := buildDelegationJWT(t, "user@example.com", "mcp-server", futureExp)

	var capturedBody map[string][]string
	var capturedUser, capturedPass string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedUser, capturedPass, _ = r.BasicAuth()
		require.NoError(t, r.ParseForm())
		capturedBody = map[string][]string(r.PostForm)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":%q}`, jwtStr)
	}))
	t.Cleanup(srv.Close)

	_, err := ExchangeTokens("my-subject-tok", "my-actor-tok", srv.URL, "ibm-client-id", "ibm-secret")
	require.NoError(t, err)

	assert.Equal(t, "ibm-client-id", capturedUser)
	assert.Equal(t, "ibm-secret", capturedPass)
	assert.Empty(t, capturedBody["client_id"], "client_id must not appear in body when Basic auth is used")
}
