// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hashicorp/vault-mcp-server/pkg/vault"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
)

// listSecrets creates a tool for listing secrets in a Vault KV mount
func listSecrets(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("listSecrets",
			mcp.WithDescription("List secrets in a KV mount under a specific path in Vault"),
			mcp.WithString("mount", mcp.Required(), mcp.Description("The mount path of the secret engine")),
			mcp.WithString("path", mcp.Description("The path to list secrets from (defaults to root)")),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return listSecretsHandler(ctx, req, logger)
		},
	}
}

func listSecretsHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling listSecrets request")

	// Extract parameters
	var mount, path string

	if req.Params.Arguments != nil {
		if args, ok := req.Params.Arguments.(map[string]interface{}); ok {
			if mount, ok = args["mount"].(string); !ok || mount == "" {
				return mcp.NewToolResultError("Missing or invalid 'mount' parameter"), nil
			}

			path, _ = args["path"].(string)
			if path == "" {
				path = ""
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
	}).Debug("Listing secrets")

	// Get Vault client from context
	client, err := vault.GetVaultClientFromContext(ctx)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	// Construct the full path for listing
	var fullPath string
	if path == "" {
		fullPath = fmt.Sprintf("%s/metadata/", strings.TrimSuffix(mount, "/"))
	} else {
		fullPath = fmt.Sprintf("%s/metadata/%s", strings.TrimSuffix(mount, "/"), strings.TrimPrefix(path, "/"))
	}

	// List secrets
	secret, err := client.Logical().List(fullPath)
	if err != nil {
		logger.WithError(err).WithFields(log.Fields{
			"mount":     mount,
			"path":      path,
			"full_path": fullPath,
		}).Error("Failed to list secrets")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to list secrets: %v", err)), nil
	}

	if secret == nil || secret.Data == nil {
		logger.WithFields(log.Fields{
			"mount": mount,
			"path":  path,
		}).Debug("No secrets found")
		return mcp.NewToolResultText("[]"), nil
	}

	// Extract keys from the response
	keys, ok := secret.Data["keys"].([]interface{})
	if !ok {
		logger.WithFields(log.Fields{
			"mount": mount,
			"path":  path,
		}).Debug("No keys found in response")
		return mcp.NewToolResultText("[]"), nil
	}

	// Convert to string slice
	var secretNames []string
	for _, key := range keys {
		if keyStr, ok := key.(string); ok {
			secretNames = append(secretNames, keyStr)
		}
	}

	// Marshal to JSON
	jsonData, err := json.Marshal(secretNames)
	if err != nil {
		logger.WithError(err).Error("Failed to marshal secrets to JSON")
		return mcp.NewToolResultError(fmt.Sprintf("Error marshaling JSON: %v", err)), nil
	}

	logger.WithFields(log.Fields{
		"mount":        mount,
		"path":         path,
		"secret_count": len(secretNames),
	}).Debug("Successfully listed secrets")

	return mcp.NewToolResultText(string(jsonData)), nil
}
