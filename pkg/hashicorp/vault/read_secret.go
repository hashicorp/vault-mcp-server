// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
)

// ReadSecret creates a tool for reading secrets from a Vault KV mount
func ReadSecret(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("read-secret",
			mcp.WithDescription("Read a secret from a KV mount in Vault"),
			mcp.WithString("mount", mcp.Required(), mcp.Description("The mount path of the secret engine")),
			mcp.WithString("path", mcp.Required(), mcp.Description("The full path to read the secret from")),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return readSecretHandler(ctx, req, logger)
		},
	}
}

func readSecretHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling read-secret request")

	// Extract parameters
	var mount, path string

	if req.Params.Arguments != nil {
		if args, ok := req.Params.Arguments.(map[string]interface{}); ok {
			if mount, ok = args["mount"].(string); !ok || mount == "" {
				return mcp.NewToolResultError("Missing or invalid 'mount' parameter"), nil
			}

			if path, ok = args["path"].(string); !ok || path == "" {
				return mcp.NewToolResultError("Missing or invalid 'path' parameter"), nil
			}
		} else {
			return mcp.NewToolResultError("Invalid arguments format"), nil
		}
	} else {
		return mcp.NewToolResultError("Missing arguments"), nil
	}

	logger.WithFields(log.Fields{
		"mount": mount,
		"path":  path,
	}).Debug("Reading secret")

	// Get Vault client from context
	client, err := GetVaultClientFromContext(ctx)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	// Construct the full path for reading (KV v2 format)
	fullPath := fmt.Sprintf("%s/data/%s", strings.TrimSuffix(mount, "/"), strings.TrimPrefix(path, "/"))

	// Read the secret
	secret, err := client.Logical().Read(fullPath)
	if err != nil {
		logger.WithError(err).WithFields(log.Fields{
			"mount":     mount,
			"path":      path,
			"full_path": fullPath,
		}).Error("Failed to read secret")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to read secret: %v", err)), nil
	}

	if secret == nil {
		logger.WithFields(log.Fields{
			"mount": mount,
			"path":  path,
		}).Debug("Secret not found")
		return mcp.NewToolResultError(fmt.Sprintf("Secret not found at path '%s' in mount '%s'", path, mount)), nil
	}

	// For KV v2, the actual data is nested under "data"
	var secretData interface{}
	if data, ok := secret.Data["data"]; ok {
		secretData = data
	} else {
		// Fallback for KV v1 or other secret engines
		secretData = secret.Data
	}

	// Marshal to JSON
	jsonData, err := json.Marshal(secretData)
	if err != nil {
		logger.WithError(err).Error("Failed to marshal secret to JSON")
		return mcp.NewToolResultError(fmt.Sprintf("Error marshaling JSON: %v", err)), nil
	}

	logger.WithFields(log.Fields{
		"mount": mount,
		"path":  path,
	}).Debug("Successfully read secret")

	return mcp.NewToolResultText(string(jsonData)), nil
}
