// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package auth

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExchangeTokens_PrivateKeyJWT(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)

	for _, format := range []struct {
		name string
		der  []byte
	}{
		{"RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key)},
		{"PRIVATE KEY", pkcs8},
	} {
		t.Run(format.name, func(t *testing.T) {
			keyPath := filepath.Join(t.TempDir(), "private.pem")
			require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: format.name, Bytes: format.der}), 0600))
			t.Setenv("VAULT_MCP_STS_PRIVATE_KEY_FILE", keyPath)
			t.Setenv("VAULT_MCP_STS_KEY_ID", "test-key")
			t.Setenv("VAULT_MCP_STS_ASSERTION_AUDIENCE", "")

			var assertions []string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Empty(t, r.Header.Get("Authorization"))
				if err := r.ParseForm(); !assert.NoError(t, err) {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				assert.Equal(t, "test-client", r.PostForm.Get("client_id"))
				assert.Empty(t, r.PostForm.Get("client_secret"))
				assert.Equal(t, "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", r.PostForm.Get("client_assertion_type"))
				assert.Equal(t, "subject", r.PostForm.Get("subject_token"))
				assert.Equal(t, "actor", r.PostForm.Get("actor_token"))
				assert.Equal(t, grantTypeTokenExchange, r.PostForm.Get("grant_type"))
				assertions = append(assertions, r.PostForm.Get("client_assertion"))
				fmt.Fprintf(w, `{"access_token":%q}`, buildDelegationJWT(t, "user", "actor", time.Now().Add(time.Hour).Unix()))
			}))
			t.Cleanup(srv.Close)

			var previousJTI string
			for _, audience := range []string{srv.URL, "https://custom-audience.example"} {
				if audience != srv.URL {
					t.Setenv("VAULT_MCP_STS_ASSERTION_AUDIENCE", audience)
				}
				_, err := ExchangeTokens("subject", "actor", srv.URL, "test-client", "ignored-secret", "")
				require.NoError(t, err)
				parts := strings.Split(assertions[len(assertions)-1], ".")
				require.Len(t, parts, 3)
				headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
				require.NoError(t, err)
				var header map[string]string
				require.NoError(t, json.Unmarshal(headerBytes, &header))
				assert.Equal(t, "RS256", header["alg"])
				assert.Equal(t, "test-key", header["kid"])
				claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
				require.NoError(t, err)
				var claims struct {
					Iss, Sub, Aud, Jti string
					Iat, Exp           int64
				}
				require.NoError(t, json.Unmarshal(claimsBytes, &claims))
				assert.Equal(t, "test-client", claims.Iss)
				assert.Equal(t, "test-client", claims.Sub)
				assert.Equal(t, audience, claims.Aud)
				assert.Equal(t, int64(60), claims.Exp-claims.Iat)
				assert.InDelta(t, time.Now().Unix(), claims.Iat, 5)
				assert.NotEmpty(t, claims.Jti)
				assert.NotEqual(t, previousJTI, claims.Jti)
				previousJTI = claims.Jti
				signature, err := base64.RawURLEncoding.DecodeString(parts[2])
				require.NoError(t, err)
				digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
				require.NoError(t, rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], signature))
			}
		})
	}
}

func TestExchangeTokens_PrivateKeyErrors(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "private.pem")
	t.Setenv("VAULT_MCP_STS_PRIVATE_KEY_FILE", keyPath)
	_, err := ExchangeTokens("subject", "actor", "http://unused", "client", "secret", "")
	require.ErrorContains(t, err, "reading private key")

	require.NoError(t, os.WriteFile(keyPath, []byte("not PEM"), 0600))
	_, err = ExchangeTokens("subject", "actor", "http://unused", "client", "secret", "")
	require.ErrorContains(t, err, "private key must be")

	_, err = ExchangeTokens("subject", "actor", "http://unused", "", "", "")
	require.ErrorContains(t, err, "STS client ID is required")
}

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

	result, err := ExchangeTokens("subject-tok", "actor-tok", srv.URL, "ibm-client", "", "")
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

	result, err := ExchangeTokens("subject-tok", "actor-tok", srv.URL, "ibm-client", "", "")
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

	result, err := ExchangeTokens("subject-tok", "actor-tok", srv.URL, "ibm-client", "", "")
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

	result, err := ExchangeTokens("subject-tok", "actor-tok", srv.URL, "ibm-client", "", "")
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

	result, err := ExchangeTokens("subject-tok", "actor-tok", srv.URL, "ibm-client", "", "")
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

	_, err := ExchangeTokens("my-subject-tok", "my-actor-tok", srv.URL, "ibm-client-id", "", "")
	require.NoError(t, err)

	assert.Equal(t, []string{grantTypeTokenExchange}, capturedBody["grant_type"])
	assert.Equal(t, []string{"my-subject-tok"}, capturedBody["subject_token"])
	assert.Equal(t, []string{tokenTypeAccessToken}, capturedBody["subject_token_type"])
	assert.Equal(t, []string{"my-actor-tok"}, capturedBody["actor_token"])
	assert.Equal(t, []string{tokenTypeAccessToken}, capturedBody["actor_token_type"])
	assert.Equal(t, []string{"ibm-client-id"}, capturedBody["client_id"])
	assert.Empty(t, capturedBody["authorization_details"], "authorization_details must not appear when empty")
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

	_, err := ExchangeTokens("my-subject-tok", "my-actor-tok", srv.URL, "ibm-client-id", "ibm-secret", "")
	require.NoError(t, err)

	assert.Equal(t, "ibm-client-id", capturedUser)
	assert.Equal(t, "ibm-secret", capturedPass)
	assert.Empty(t, capturedBody["client_id"], "client_id must not appear in body when Basic auth is used")
}

// TestExchangeTokens_AuthorizationDetails_Sent: verifies that a non-empty
// authorizationDetails value is forwarded as the authorization_details POST parameter.
func TestExchangeTokens_AuthorizationDetails_Sent(t *testing.T) {
	futureExp := time.Now().Add(1 * time.Hour).Unix()
	jwtStr := buildDelegationJWT(t, "user@example.com", "mcp-server", futureExp)

	const authzDetails = `[{"type":"vault:path_access","path":"secret-v2/data/shared-secret/foo","capabilities":["create","update","read"]}]`

	var capturedBody map[string][]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		capturedBody = map[string][]string(r.PostForm)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":%q}`, jwtStr)
	}))
	t.Cleanup(srv.Close)

	_, err := ExchangeTokens("my-subject-tok", "my-actor-tok", srv.URL, "ibm-client-id", "", authzDetails)
	require.NoError(t, err)

	assert.Equal(t, []string{authzDetails}, capturedBody["authorization_details"])
}

// TestExchangeTokens_AuthorizationDetails_Empty: verifies that when authorizationDetails
// is empty, the authorization_details parameter is absent from the POST body.
func TestExchangeTokens_AuthorizationDetails_Empty(t *testing.T) {
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

	_, err := ExchangeTokens("my-subject-tok", "my-actor-tok", srv.URL, "ibm-client-id", "", "")
	require.NoError(t, err)

	assert.Empty(t, capturedBody["authorization_details"])
}
