// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package kv

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hashicorp/vault-mcp-server/pkg/client"
	"github.com/hashicorp/vault-mcp-server/pkg/utils"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
)

// ReadSecretMetadata creates a tool for reading secret metadata from a Vault KV v2 mount
func ReadSecretMetadata(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("read_secret_metadata",
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					ReadOnlyHint:    utils.ToBoolPtr(true),
					IdempotentHint:  utils.ToBoolPtr(true),
				},
			),
			mcp.WithDescription("Read metadata for a secret from a KV v2 mount in Vault. Returns version history, custom metadata, and configuration like max_versions and cas_required. Only supported on KV v2 mounts."),
			mcp.WithString("mount",
				mcp.Required(),
				mcp.Description("The mount path of the secret engine. For example, if you want to read metadata from 'secrets/application/credentials', this should be 'secrets' without the trailing slash."),
			),
			mcp.WithString("path",
				mcp.Required(),
				mcp.Description("The full path to the secret without the mount prefix. For example, if you want to read metadata from 'secrets/application/credentials', this should be 'application/credentials'."),
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return readSecretMetadataHandler(ctx, req, logger)
		},
	}
}

func readSecretMetadataHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling read_secret_metadata request")

	// Extract parameters
	args, ok := req.Params.Arguments.(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("Missing or invalid arguments format"), nil
	}

	mount, err := utils.ExtractMountPath(args)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	path, ok := args["path"].(string)
	if !ok || path == "" {
		return mcp.NewToolResultError("Missing or invalid 'path' parameter"), nil
	}

	logger.WithFields(log.Fields{
		"mount": mount,
		"path":  path,
	}).Debug("Reading secret metadata")

	// Get Vault client from context
	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	isV2, err := getMountInfo(vault, mount)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	if !isV2 {
		return mcp.NewToolResultError("read_secret_metadata is only supported on KV v2 mounts"), nil
	}

	// Read metadata at mount/metadata/path
	fullPath := fmt.Sprintf("%s/metadata/%s", mount, strings.TrimPrefix(path, "/"))
	secret, err := vault.Logical().Read(fullPath)
	if err != nil {
		logger.WithError(err).WithFields(log.Fields{
			"mount":     mount,
			"path":      path,
			"full_path": fullPath,
		}).Error("Failed to read secret metadata")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to read secret metadata: %v", err)), nil
	}

	if secret == nil {
		return mcp.NewToolResultError(fmt.Sprintf("No metadata found at path '%s' in mount '%s'", path, mount)), nil
	}

	// Marshal to JSON
	jsonData, err := json.Marshal(secret.Data)
	if err != nil {
		logger.WithError(err).Error("Failed to marshal metadata to JSON")
		return mcp.NewToolResultError(fmt.Sprintf("Error marshaling JSON: %v", err)), nil
	}

	logger.WithFields(log.Fields{
		"mount": mount,
		"path":  path,
	}).Debug("Successfully read secret metadata")

	return mcp.NewToolResultText(string(jsonData)), nil
}
