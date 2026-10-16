// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package auth

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPasswordGrant: sends grant_type=password with the actor credentials and
// authenticates the client with client_secret_basic.
func TestPasswordGrant(t *testing.T) {
	var cap capturedTokenRequest
	srv := newFakeTokenServerCapture(t, "actor-tok", 0, &cap)

	res := PasswordGrant(PKCEConfig{
		ClientID:     "my-client",
		ClientSecret: "my-secret",
		TokenURL:     srv.URL,
	}, "agent-user", "agent-pass")

	require.NoError(t, res.Err)
	assert.Equal(t, "actor-tok", res.Token.AccessToken)
	assert.Equal(t, "password", cap.Body.Get("grant_type"))
	assert.Equal(t, "agent-user", cap.Body.Get("username"))
	assert.Equal(t, "agent-pass", cap.Body.Get("password"))
	assert.True(t, strings.HasPrefix(cap.AuthHeader, "Basic "))
}

// TestPasswordGrant_Error: a non-2xx token response surfaces as an error.
func TestPasswordGrant_Error(t *testing.T) {
	srv := newFakeTokenServer(t, "", 401)

	res := PasswordGrant(PKCEConfig{ClientID: "c", TokenURL: srv.URL}, "u", "bad")

	require.Error(t, res.Err)
	assert.Contains(t, res.Err.Error(), "401")
}
