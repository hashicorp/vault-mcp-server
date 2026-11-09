// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestClientCredentialsGrant: sends grant_type=client_credentials and
// authenticates the client with client_secret_post.
func TestClientCredentialsGrant(t *testing.T) {
	var cap capturedTokenRequest
	srv := newFakeTokenServerCapture(t, "actor-tok", 0, &cap)

	res := ClientCredentialsGrant(PKCEConfig{
		ClientID:     "my-client",
		ClientSecret: "my-secret",
		TokenURL:     srv.URL,
		Scopes:       []string{"openid"},
	})

	require.NoError(t, res.Err)
	assert.Equal(t, "actor-tok", res.Token.AccessToken)
	assert.Equal(t, "client_credentials", cap.Body.Get("grant_type"))
	assert.Equal(t, "openid", cap.Body.Get("scope"))
	assert.Empty(t, cap.Body.Get("username"))
	assert.Equal(t, "my-client", cap.Body.Get("client_id"))
	assert.Equal(t, "my-secret", cap.Body.Get("client_secret"))
	assert.Empty(t, cap.AuthHeader)
}

// TestClientCredentialsGrant_Error: a non-2xx token response surfaces as an error.
func TestClientCredentialsGrant_Error(t *testing.T) {
	srv := newFakeTokenServer(t, "", 401)

	res := ClientCredentialsGrant(PKCEConfig{ClientID: "c", ClientSecret: "bad", TokenURL: srv.URL})

	require.Error(t, res.Err)
	assert.Contains(t, res.Err.Error(), "401")
}

// TestClientCredentialsGrant_RequiresSecret: a public client cannot use this grant.
func TestClientCredentialsGrant_RequiresSecret(t *testing.T) {
	for _, cfg := range []PKCEConfig{{ClientID: "c"}, {ClientSecret: "s"}, {}} {
		res := ClientCredentialsGrant(cfg)
		assert.ErrorIs(t, res.Err, ErrActorCredentialsMissing)
	}
}
