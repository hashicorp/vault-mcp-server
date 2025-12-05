// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package kv

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/hashicorp/vault-mcp-server/pkg/client"
	"github.com/hashicorp/vault-mcp-server/pkg/utils"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
)

// ListSecrets creates a tool for listing secrets in a Vault KV mount
func ListSecrets(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("list_secrets",
			mcp.WithDescription("List secrets in a KV mount under a specific path in Vault"),
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					ReadOnlyHint: utils.ToBoolPtr(true),
				},
			),
			mcp.WithString("mount",
				mcp.Required(),
				mcp.Description("The mount path of the secret engine. For example, if you want to list 'secrets/application/credentials', this should be 'secrets' without the trailing slash."),
			),
			mcp.WithString("path",
				mcp.DefaultString(""),
				mcp.Description("The full path to list the secrets to without the mount prefix. For example, if you want to list from 'secrets/application/credentials', this should be 'application/credentials'.")),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return listSecretsHandler(ctx, req, logger)
		},
	}
}

func listSecretsHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling list_secrets request")

	// Extract parameters
	args, ok := req.Params.Arguments.(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("Missing or invalid arguments format"), nil
	}

	mount, err := utils.ExtractMountPath(args)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	path, _ := args["path"].(string)
	if path == "" {
		path = ""
	}

	logger.WithFields(log.Fields{
		"mount": mount,
		"path":  path,
	}).Debug("Listing secrets")

	// Get Vault client from context
	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	// Construct the full path for listing
	fullPath := fmt.Sprintf(mount+"/%s", path)

	mounts, err := vault.Sys().ListMounts()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to list mounts: %v", err)), nil
	}

	// Check if the mount exists
	if m, ok := mounts[mount+"/"]; ok {
		// is it a KV v2 mount?
		if m.Options["version"] == "2" {
			if path == "" {
				fullPath = fmt.Sprintf("%s/metadata/", mount)
			} else {
				fullPath = fmt.Sprintf("%s/metadata/%s", mount, strings.TrimPrefix(path, "/"))
			}
		}
	} else {
		return mcp.NewToolResultError(fmt.Sprintf("mount path '%s' does not exist. Use 'create_mount' with the type kv2 to create the mount.", mount)), nil
	}

	// List secrets
	secret, err := vault.Logical().List(fullPath)
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
