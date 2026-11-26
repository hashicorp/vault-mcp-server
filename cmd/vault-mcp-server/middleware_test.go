// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hashicorp/vault-mcp-server/pkg/auth"
	"github.com/mark3labs/mcp-go/mcp"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// callTool registers a tool named name on a new server, calls it and reports
// whether the handler ran and what text the caller saw.
func callTool(t *testing.T, name string) (handlerRan bool, text string) {
	t.Helper()
	logger := log.New()
	logger.SetLevel(log.PanicLevel)
	s := NewServer("test", logger, nil)
	s.AddTool(mcp.NewTool(name), func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handlerRan = true
		return mcp.NewToolResultText("handler ran"), nil
	})

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + name + `","arguments":{}}}`
	resp := s.HandleMessage(context.Background(), json.RawMessage(body))
	raw, err := json.Marshal(resp)
	require.NoError(t, err)
	var parsed struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	require.NoError(t, json.Unmarshal(raw, &parsed))
	require.NotEmpty(t, parsed.Result.Content, string(raw))
	return handlerRan, parsed.Result.Content[0].Text
}

// nearExpiryJWT is a JWT inside its renewal window.
func nearExpiryJWT() *auth.DelegationJWT {
	return &auth.DelegationJWT{Sub: "user", Exp: time.Now().Add(10 * time.Second), Iat: time.Now().Add(-time.Hour), Raw: "jwt"}
}

// expiredSubjectResult is a login result whose Subject token expired a minute
// ago and has no refresh token.
func expiredSubjectResult() *auth.PKCEResult {
	now := time.Now()
	return &auth.PKCEResult{
		SubjectToken:     "expired",
		SubjectIssuedAt:  now.Add(-time.Hour),
		SubjectExpiresAt: now.Add(-time.Minute),
	}
}

func useTokenSource(t *testing.T, ts *auth.TokenSource) {
	t.Helper()
	t.Setenv("VAULT_MCP_AUTH_ENABLED", "true")
	activeTokenSource.Store(ts)
	t.Cleanup(func() { activeTokenSource.Store(nil) })
}

func TestJWTMiddleware_RenewalFailures(t *testing.T) {
	t.Run("reauthentication required", func(t *testing.T) {
		// An expired Subject token without a refresh token cannot be renewed.
		ts := auth.NewTokenSource(auth.AuthConfig{}, nearExpiryJWT(), expiredSubjectResult())
		useTokenSource(t, ts)

		ran, text := callTool(t, "kv_read")

		assert.False(t, ran)
		assert.Equal(t, "Re-authentication required. Call vault_login.", text)

		// Every later call gets the same message, not "Not authenticated".
		ran, text = callTool(t, "kv_read")

		assert.False(t, ran)
		assert.Equal(t, "Re-authentication required. Call vault_login.", text)
	})

	t.Run("transient failure does not leak details", func(t *testing.T) {
		idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "internal secret detail", http.StatusServiceUnavailable)
		}))
		t.Cleanup(idp.Close)
		ts := auth.NewTokenSource(auth.AuthConfig{TokenURL: idp.URL}, nearExpiryJWT(),
			&auth.PKCEResult{SubjectRefreshToken: "rt"})
		useTokenSource(t, ts)

		ran, text := callTool(t, "kv_read")

		assert.False(t, ran)
		assert.Contains(t, text, "Could not renew Vault credentials")
		assert.NotContains(t, text, "internal secret detail")
	})

	t.Run("login tools skip renewal", func(t *testing.T) {
		ts := auth.NewTokenSource(auth.AuthConfig{}, nearExpiryJWT(), expiredSubjectResult())
		useTokenSource(t, ts)

		ran, text := callTool(t, "vault_login")

		assert.True(t, ran)
		assert.Equal(t, "handler ran", text)
	})
}
