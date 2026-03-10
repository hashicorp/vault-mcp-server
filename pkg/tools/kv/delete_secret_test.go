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

func TestDeleteSecretHandler_DeleteKeyFromV2(t *testing.T) {
	logger := newLogger()
	var capturedBody map[string]interface{}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/sys/mounts", func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, mountsV2Response("secrets"))
	})
	mux.HandleFunc("/v1/secrets/data/app/creds", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			jsonResponse(w, map[string]interface{}{
				"data": map[string]interface{}{
					"data": map[string]interface{}{
						"username": "admin",
						"password": "secret123",
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
			Name: "delete_secret",
			Arguments: map[string]interface{}{
				"mount": "secrets",
				"path":  "app/creds",
				"key":   "password",
			},
		},
	}

	result, err := deleteSecretHandler(ctx, req, logger)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.IsError, "expected success, got error: %s", getResultText(result))

	// Verify the written data has the correct KV v2 wrapper structure
	require.NotNil(t, capturedBody, "expected a write to Vault")
	dataField, ok := capturedBody["data"].(map[string]interface{})
	require.True(t, ok, "written body should have 'data' wrapper for KV v2")
	assert.Equal(t, "admin", dataField["username"], "remaining key should be preserved")
	_, hasDeleted := dataField["password"]
	assert.False(t, hasDeleted, "deleted key should not be present")
}

func TestDeleteSecretHandler_SoftDeletedSecretV2(t *testing.T) {
	logger := newLogger()

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/sys/mounts", func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, mountsV2Response("secrets"))
	})
	mux.HandleFunc("/v1/secrets/data/app/old", func(w http.ResponseWriter, r *http.Request) {
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
	})

	ctx, cleanup := newTestContext(t, mux)
	defer cleanup()

	req := mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name: "delete_secret",
			Arguments: map[string]interface{}{
				"mount": "secrets",
				"path":  "app/old",
				"key":   "some-key",
			},
		},
	}

	result, err := deleteSecretHandler(ctx, req, logger)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.IsError, "deleting from a soft-deleted secret should return an error")
	assert.Contains(t, getResultText(result), "deleted")
}
