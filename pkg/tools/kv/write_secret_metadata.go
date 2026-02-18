// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package kv

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/vault-mcp-server/pkg/client"
	"github.com/hashicorp/vault-mcp-server/pkg/utils"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
)

// WriteSecretMetadata creates a tool for writing secret metadata to a Vault KV v2 mount
func WriteSecretMetadata(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("write_secret_metadata",
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					DestructiveHint: utils.ToBoolPtr(true),
					IdempotentHint:  utils.ToBoolPtr(false),
				},
			),
			mcp.WithDescription("Write metadata configuration for a secret in a KV v2 mount in Vault. Allows setting max_versions, cas_required, delete_version_after, and custom_metadata. Only supported on KV v2 mounts."),
			mcp.WithString("mount",
				mcp.Required(),
				mcp.Description("The mount path of the secret engine."),
			),
			mcp.WithString("path",
				mcp.Required(),
				mcp.Description("The full path to the secret without the mount prefix."),
			),
			mcp.WithNumber("max_versions",
				mcp.Description("The maximum number of versions to keep for the secret. If not set, the backend's configured max version is used."),
			),
			mcp.WithBoolean("cas_required",
				mcp.Description("If true, the backend will require the cas parameter to be set on every write."),
			),
			mcp.WithString("delete_version_after",
				mcp.Description("The duration after which a version is deleted. Accepts Go duration format (e.g. '3h25m', '72h')."),
			),
			mcp.WithObject("custom_metadata",
				mcp.Description("A map of arbitrary string key-value pairs to store as custom metadata for the secret."),
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return writeSecretMetadataHandler(ctx, req, logger)
		},
	}
}

func writeSecretMetadataHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling write_secret_metadata request")

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
	}).Debug("Writing secret metadata")

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
		return mcp.NewToolResultError("write_secret_metadata is only supported on KV v2 mounts"), nil
	}

	// Build data map only with provided parameters
	data := make(map[string]interface{})

	if v, ok := args["max_versions"].(float64); ok {
		data["max_versions"] = int(v)
	}
	if v, ok := args["cas_required"].(bool); ok {
		data["cas_required"] = v
	}
	if v, ok := args["delete_version_after"].(string); ok {
		data["delete_version_after"] = v
	}
	if v, ok := args["custom_metadata"].(map[string]interface{}); ok {
		data["custom_metadata"] = v
	}

	if len(data) == 0 {
		return mcp.NewToolResultError("At least one metadata field must be provided (max_versions, cas_required, delete_version_after, or custom_metadata)"), nil
	}

	// Write metadata at mount/metadata/path
	fullPath := fmt.Sprintf("%s/metadata/%s", mount, strings.TrimPrefix(path, "/"))
	_, err = vault.Logical().Write(fullPath, data)
	if err != nil {
		logger.WithError(err).WithFields(log.Fields{
			"mount":     mount,
			"path":      path,
			"full_path": fullPath,
		}).Error("Failed to write secret metadata")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to write secret metadata: %v", err)), nil
	}

	logger.WithFields(log.Fields{
		"mount": mount,
		"path":  path,
	}).Info("Successfully wrote secret metadata")

	return mcp.NewToolResultText(fmt.Sprintf("Successfully wrote metadata for secret at path '%s' in mount '%s'", path, mount)), nil
}
