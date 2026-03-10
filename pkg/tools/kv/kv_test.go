// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package kv

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
