// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package kv

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/hashicorp/vault-mcp-server/pkg/client"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

// fakeSession implements server.ClientSession for testing.
type fakeSession struct {
	id      string
	notifCh chan mcp.JSONRPCNotification
}

func (f fakeSession) Initialize()                                        {}
func (f fakeSession) Initialized() bool                                  { return true }
func (f fakeSession) NotificationChannel() chan<- mcp.JSONRPCNotification { return f.notifCh }
func (f fakeSession) SessionID() string                                  { return f.id }

// newTestContext creates a context wired to a mock Vault HTTP server.
// The returned cleanup function must be deferred.
func newTestContext(t *testing.T, handler http.Handler) (context.Context, func()) {
	t.Helper()
	mockVault := httptest.NewServer(handler)

	sessionID := "test-" + t.Name()
	_, err := client.NewVaultClient(sessionID, mockVault.URL, false, "test-token", "")
	require.NoError(t, err)

	mcpSrv := server.NewMCPServer("test", "1.0")
	ctx := mcpSrv.WithContext(context.Background(), fakeSession{
		id:      sessionID,
		notifCh: make(chan mcp.JSONRPCNotification, 10),
	})

	return ctx, func() {
		mockVault.Close()
		client.DeleteVaultClient(sessionID)
	}
}

func newLogger() *log.Logger {
	logger := log.New()
	logger.SetLevel(log.ErrorLevel)
	return logger
}

func jsonResponse(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

// mountsV2Response returns a Vault sys/mounts response for a KV v2 mount.
func mountsV2Response(mount string) map[string]interface{} {
	return map[string]interface{}{
		"data": map[string]interface{}{
			mount + "/": map[string]interface{}{
				"type": "kv",
				"options": map[string]interface{}{
					"version": "2",
				},
			},
		},
	}
}

// getResultText extracts the text from a CallToolResult.
func getResultText(result *mcp.CallToolResult) string {
	if result == nil || len(result.Content) == 0 {
		return ""
	}
	tc, ok := mcp.AsTextContent(result.Content[0])
	if !ok {
		return ""
	}
	return tc.Text
}

func TestListSecretsHandler_KVV1(t *testing.T) {
	logger := newLogger()
	var calledV2 atomic.Bool

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/secrets/app", "/v1/secrets/app/":
			jsonResponse(w, map[string]interface{}{
				"data": map[string]interface{}{
					"keys": []string{"foo", "bar/"},
				},
			})
		case "/v1/secrets/metadata/app", "/v1/secrets/metadata/app/":
			calledV2.Store(true)
			w.WriteHeader(http.StatusInternalServerError)
			jsonResponse(w, map[string]interface{}{"errors": []string{"unexpected v2 fallback"}})
		case "/v1/sys/mounts":
			w.WriteHeader(http.StatusInternalServerError)
			jsonResponse(w, map[string]interface{}{"errors": []string{"unexpected sys/mounts call"}})
		default:
			w.WriteHeader(http.StatusNotFound)
			jsonResponse(w, map[string]interface{}{"errors": []string{"not found"}})
		}
	})

	ctx, cleanup := newTestContext(t, h)
	defer cleanup()

	req := mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name: "list_secrets",
			Arguments: map[string]interface{}{
				"mount": "secrets",
				"path":  "app",
			},
		},
	}

	result, err := listSecretsHandler(ctx, req, logger)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.False(t, result.IsError, getResultText(result))
	require.JSONEq(t, `["foo","bar/"]`, getResultText(result))
	require.False(t, calledV2.Load())
}

func TestListSecretsHandler_FallsBackToKVV2(t *testing.T) {
	logger := newLogger()

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/secrets/", "/v1/secrets":
			w.WriteHeader(http.StatusNotFound)
			jsonResponse(w, map[string]interface{}{"errors": []string{"unsupported path"}})
		case "/v1/secrets/metadata/", "/v1/secrets/metadata":
			jsonResponse(w, map[string]interface{}{
				"data": map[string]interface{}{
					"keys": []string{"alpha", "bravo/"},
				},
			})
		case "/v1/sys/mounts":
			// Simulate restricted Vault tokens that cannot read sys/mounts.
			w.WriteHeader(http.StatusForbidden)
			jsonResponse(w, map[string]interface{}{"errors": []string{"permission denied"}})
		default:
			w.WriteHeader(http.StatusNotFound)
			jsonResponse(w, map[string]interface{}{"errors": []string{"not found"}})
		}
	})

	ctx, cleanup := newTestContext(t, h)
	defer cleanup()

	req := mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name: "list_secrets",
			Arguments: map[string]interface{}{
				"mount": "secrets",
				"path":  "",
			},
		},
	}

	result, err := listSecretsHandler(ctx, req, logger)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.False(t, result.IsError, getResultText(result))
	require.JSONEq(t, `["alpha","bravo/"]`, getResultText(result))
}
