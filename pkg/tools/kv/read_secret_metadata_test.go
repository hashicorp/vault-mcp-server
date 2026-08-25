// Copyright IBM Corp. 2025, 2026
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

func TestReadSecretMetadataHandler_SuccessV2(t *testing.T) {
	logger := newLogger()

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/sys/mounts", func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, mountsV2Response("secrets"))
	})
	mux.HandleFunc("/v1/secrets/metadata/app/config", func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, map[string]interface{}{
			"data": map[string]interface{}{
				"created_time":    "2026-06-10T12:00:00Z",
				"updated_time":    "2026-06-10T13:00:00Z",
				"current_version": 3,
				"oldest_version":  0,
				"max_versions":    0,
			},
		})
	})

	ctx, cleanup := newTestContext(t, mux)
	defer cleanup()

	req := mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name: "read_secret_metadata",
			Arguments: map[string]interface{}{
				"mount": "secrets",
				"path":  "app/config",
			},
		},
	}

	result, err := readSecretMetadataHandler(ctx, req, logger)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.IsError, "expected success, got error: %s", getResultText(result))

	var payload map[string]interface{}
	err = json.Unmarshal([]byte(getResultText(result)), &payload)
	require.NoError(t, err)
	assert.Equal(t, "2026-06-10T12:00:00Z", payload["created_time"])
	assert.Equal(t, float64(3), payload["current_version"])
}

func TestReadSecretMetadataHandler_RejectsKVv1(t *testing.T) {
	logger := newLogger()

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/sys/mounts", func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, map[string]interface{}{
			"data": map[string]interface{}{
				"legacy/": map[string]interface{}{
					"type": "kv",
					"options": map[string]interface{}{
						"version": "1",
					},
				},
			},
		})
	})

	ctx, cleanup := newTestContext(t, mux)
	defer cleanup()

	req := mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name: "read_secret_metadata",
			Arguments: map[string]interface{}{
				"mount": "legacy",
				"path":  "app/config",
			},
		},
	}

	result, err := readSecretMetadataHandler(ctx, req, logger)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.IsError, "expected error for KV v1 mount")
	assert.Contains(t, getResultText(result), "not KV v2")
}