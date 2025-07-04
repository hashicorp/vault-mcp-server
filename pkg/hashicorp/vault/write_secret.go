// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
)

// WriteSecret creates a tool for writing secrets to a Vault KV mount
func WriteSecret(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("write-secret",
			mcp.WithDescription("Write a secret to a KV mount in Vault"),
			mcp.WithString("mount", mcp.Required(), mcp.Description("The mount path of the secret engine")),
			mcp.WithString("path", mcp.Required(), mcp.Description("The full path to write the secret to")),
			mcp.WithString("key", mcp.Required(), mcp.Description("The key name for the secret")),
			mcp.WithString("value", mcp.Required(), mcp.Description("The value to store")),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return writeSecretHandler(ctx, req, logger)
		},
	}
}

func writeSecretHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling write-secret request")

	// Extract parameters
	var mount, path, key, value string

	if req.Params.Arguments != nil {
		if args, ok := req.Params.Arguments.(map[string]interface{}); ok {
			if mount, ok = args["mount"].(string); !ok || mount == "" {
				return mcp.NewToolResultError("Missing or invalid 'mount' parameter"), nil
			}

			if path, ok = args["path"].(string); !ok || path == "" {
				return mcp.NewToolResultError("Missing or invalid 'path' parameter"), nil
			}

			if key, ok = args["key"].(string); !ok || key == "" {
				return mcp.NewToolResultError("Missing or invalid 'key' parameter"), nil
			}

			if value, ok = args["value"].(string); !ok {
				return mcp.NewToolResultError("Missing or invalid 'value' parameter"), nil
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
		"key":   key,
	}).Debug("Writing secret")

	// Get Vault client from context
	client, err := GetVaultClientFromContext(ctx)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	// Construct the full path for writing (KV v2 format)
	fullPath := fmt.Sprintf("%s/data/%s", strings.TrimSuffix(mount, "/"), strings.TrimPrefix(path, "/"))

	// Prepare the data to write
	// For KV v2, we need to wrap the data under a "data" key
	secretData := map[string]interface{}{
		"data": map[string]interface{}{
			key: value,
		},
	}

	// Write the secret
	_, err = client.Logical().Write(fullPath, secretData)
	if err != nil {
		logger.WithError(err).WithFields(log.Fields{
			"mount":     mount,
			"path":      path,
			"key":       key,
			"full_path": fullPath,
		}).Error("Failed to write secret")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to write secret: %v", err)), nil
	}

	successMsg := fmt.Sprintf("Successfully wrote secret '%s' to path '%s' in mount '%s'", key, path, mount)
	logger.WithFields(log.Fields{
		"mount": mount,
		"path":  path,
		"key":   key,
	}).Info("Successfully wrote secret")

	return mcp.NewToolResultText(successMsg), nil
}
