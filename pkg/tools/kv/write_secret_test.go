// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package kv

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteSecretHandler_SoftDeletedSecretV2(t *testing.T) {
	logger := newLogger()
	var capturedBody map[string]interface{}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/sys/mounts", func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, mountsV2Response("team/api-keys"))
	})
	mux.HandleFunc("/v1/team/api-keys/data/secrets", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			// Soft-deleted secret: data is null, metadata has deletion_time
			jsonResponse(w, map[string]interface{}{
				"data": map[string]interface{}{
					"data": nil,
					"metadata": map[string]interface{}{
						"deletion_time": "2024-01-18T03:00:00Z",
						"destroyed":     false,
						"version":       1,
					},
				},
			})
		case http.MethodPut:
			json.NewDecoder(r.Body).Decode(&capturedBody)
			jsonResponse(w, map[string]interface{}{
				"data": map[string]interface{}{
					"version":      2,
					"created_time": "2024-01-18T04:00:00Z",
				},
			})
		}
	})

	ctx, cleanup := newTestContext(t, mux)
	defer cleanup()

	req := mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name: "write_secret",
			Arguments: map[string]interface{}{
				"mount": "team/api-keys",
				"path":  "secrets",
				"key":   "api-gateway",
				"value": "newvalue123",
			},
		},
	}

	result, err := writeSecretHandler(ctx, req, logger)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.IsError, "expected success, got error: %s", getResultText(result))

	// Verify the written data has the correct KV v2 structure
	require.NotNil(t, capturedBody, "expected a write to Vault")
	dataField, ok := capturedBody["data"].(map[string]interface{})
	require.True(t, ok, "written body should have 'data' wrapper for KV v2")
	assert.Equal(t, "newvalue123", dataField["api-gateway"])
}

func TestWriteSecretHandler_ExistingSecretV2(t *testing.T) {
	logger := newLogger()
	var capturedBody map[string]interface{}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/sys/mounts", func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, mountsV2Response("secrets"))
	})
	mux.HandleFunc("/v1/secrets/data/app/config", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			jsonResponse(w, map[string]interface{}{
				"data": map[string]interface{}{
					"data": map[string]interface{}{
						"existing-key": "existing-value",
					},
					"metadata": map[string]interface{}{
						"version": 1,
					},
				},
			})
		case http.MethodPut:
			json.NewDecoder(r.Body).Decode(&capturedBody)
			jsonResponse(w, map[string]interface{}{
				"data": map[string]interface{}{
					"version": 2,
				},
			})
		}
	})

	ctx, cleanup := newTestContext(t, mux)
	defer cleanup()

	req := mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name: "write_secret",
			Arguments: map[string]interface{}{
				"mount": "secrets",
				"path":  "app/config",
				"key":   "new-key",
				"value": "new-value",
			},
		},
	}

	result, err := writeSecretHandler(ctx, req, logger)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.IsError, "expected success, got error: %s", getResultText(result))

	// Verify the written data merged new key with existing data
	require.NotNil(t, capturedBody, "expected a write to Vault")
	dataField, ok := capturedBody["data"].(map[string]interface{})
	require.True(t, ok, "written body should have 'data' wrapper for KV v2")
	assert.Equal(t, "existing-value", dataField["existing-key"], "existing key should be preserved")
	assert.Equal(t, "new-value", dataField["new-key"], "new key should be added")
}
