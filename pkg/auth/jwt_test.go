// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package auth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildToken constructs a minimal unsigned JWT string (header.payload.signature)
// from the given payload map. The header and signature are placeholders.
func buildToken(t *testing.T, payload map[string]interface{}) string {
	t.Helper()
	b, err := json.Marshal(payload)
	require.NoError(t, err)
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payloadEnc := base64.RawURLEncoding.EncodeToString(b)
	return strings.Join([]string{header, payloadEnc, "fakesig"}, ".")
}

func TestParseUnsigned_ValidPayload(t *testing.T) {
	// Given a valid JWT payload → ParseUnsigned returns a DelegationJWT with
	// correct Sub, Act, Exp, AuthorizationDetails.
	futureExp := time.Now().Add(1 * time.Hour).Unix()
	authDetails := []map[string]interface{}{
		{"type": "vault:path_access", "path": "secret/data/foo", "capabilities": []string{"read"}},
	}
	payload := map[string]interface{}{
		"sub": "user@example.com",
		"act": map[string]string{"sub": "mcp-server"},
		"exp": futureExp,
		"authorization_details": authDetails,
	}

	token := buildToken(t, payload)
	jwt, err := ParseUnsigned(token)

	require.NoError(t, err)
	require.NotNil(t, jwt)

	assert.Equal(t, "user@example.com", jwt.Sub)
	assert.Equal(t, "mcp-server", jwt.Act.Sub)
	assert.Equal(t, time.Unix(futureExp, 0), jwt.Exp)
	assert.Len(t, jwt.AuthorizationDetails, 1)
	assert.Equal(t, token, jwt.Raw)

	// Verify the authorization_details element round-trips as JSON.
	var detail map[string]interface{}
	require.NoError(t, json.Unmarshal(jwt.AuthorizationDetails[0], &detail))
	assert.Equal(t, "vault:path_access", detail["type"])
	assert.Equal(t, "secret/data/foo", detail["path"])
}

func TestParseUnsigned_ExpiredToken(t *testing.T) {
	// Given a JWT where exp is in the past → ParseUnsigned returns ErrTokenExpired.
	pastExp := time.Now().Add(-1 * time.Hour).Unix()
	payload := map[string]interface{}{
		"sub": "user@example.com",
		"act": map[string]string{"sub": "mcp-server"},
		"exp": pastExp,
	}

	token := buildToken(t, payload)
	jwt, err := ParseUnsigned(token)

	assert.Nil(t, jwt)
	assert.True(t, errors.Is(err, ErrTokenExpired),
		"expected ErrTokenExpired, got: %v", err)
}

func TestParseUnsigned_MalformedBase64(t *testing.T) {
	// Given a malformed base64 payload → ParseUnsigned returns a parse error (not a panic).
	// Construct a token whose second segment is not valid base64url.
	malformedToken := "eyJhbGciOiJub25lIn0.!!!notbase64!!.fakesig"

	assert.NotPanics(t, func() {
		jwt, err := ParseUnsigned(malformedToken)
		assert.Nil(t, jwt)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "auth:")
	})
}

func TestParseUnsigned_WrongSegmentCount(t *testing.T) {
	// A token without the right number of '.' segments must fail cleanly.
	tests := []struct {
		name  string
		token string
	}{
		{"only one segment", "onlyone"},
		{"two segments", "header.payload"},
		{"four segments", "a.b.c.d"},
		{"empty string", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.NotPanics(t, func() {
				jwt, err := ParseUnsigned(tt.token)
				assert.Nil(t, jwt)
				assert.Error(t, err)
			})
		})
	}
}

func TestParseUnsigned_InvalidJSON(t *testing.T) {
	// Valid base64url payload that is not valid JSON.
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	badPayload := base64.RawURLEncoding.EncodeToString([]byte(`not-json`))
	token := fmt.Sprintf("%s.%s.sig", header, badPayload)

	assert.NotPanics(t, func() {
		jwt, err := ParseUnsigned(token)
		assert.Nil(t, jwt)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "auth:")
	})
}

func TestParseUnsigned_ZeroExp(t *testing.T) {
	// A payload with exp=0 (not set) must not be treated as expired.
	payload := map[string]interface{}{
		"sub": "user@example.com",
		"act": map[string]string{"sub": "mcp-server"},
		"exp": 0,
	}

	token := buildToken(t, payload)
	jwt, err := ParseUnsigned(token)

	require.NoError(t, err, "exp=0 must not trigger ErrTokenExpired")
	require.NotNil(t, jwt)
	assert.Equal(t, "user@example.com", jwt.Sub)
}

func TestParseUnsigned_RawPreserved(t *testing.T) {
	// jwt.Raw must be identical to the input token string.
	futureExp := time.Now().Add(1 * time.Hour).Unix()
	payload := map[string]interface{}{
		"sub": "user@example.com",
		"exp": futureExp,
	}

	token := buildToken(t, payload)
	jwt, err := ParseUnsigned(token)

	require.NoError(t, err)
	assert.Equal(t, token, jwt.Raw)
}
