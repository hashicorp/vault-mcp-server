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

// PatchSecret creates a tool for patching secrets in a Vault KV v2 mount
func PatchSecret(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("patch_secret",
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					DestructiveHint: utils.ToBoolPtr(true),
					IdempotentHint:  utils.ToBoolPtr(false),
				},
			),
			mcp.WithDescription("Patch a secret in a KV v2 mount in Vault. Merges the provided data with the existing secret data without replacing unspecified keys. Uses HTTP PATCH with JSON merge patch semantics. Only supported on KV v2 mounts."),
			mcp.WithString("mount",
				mcp.Required(),
				mcp.Description("The mount path of the secret engine."),
			),
			mcp.WithString("path",
				mcp.Required(),
				mcp.Description("The full path to the secret without the mount prefix."),
			),
			mcp.WithObject("data",
				mcp.Required(),
				mcp.Description("A key-value map of the secret data to merge. Only the specified keys will be updated; unspecified keys remain unchanged. For example: {\"password\": \"new_password\"} will update only the password key."),
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return patchSecretHandler(ctx, req, logger)
		},
	}
}

func patchSecretHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling patch_secret request")

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

	data, ok := args["data"].(map[string]interface{})
	if !ok || data == nil {
		return mcp.NewToolResultError("Missing or invalid 'data' parameter — must be a JSON object"), nil
	}

	logger.WithFields(log.Fields{
		"mount": mount,
		"path":  path,
	}).Debug("Patching secret")

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
		return mcp.NewToolResultError("patch_secret is only supported on KV v2 mounts"), nil
	}

	// Patch at mount/data/path using JSON merge patch
	fullPath := fmt.Sprintf("%s/data/%s", mount, strings.TrimPrefix(path, "/"))
	versionInfo, err := vault.Logical().JSONMergePatch(ctx, fullPath, map[string]interface{}{
		"data": data,
	})
	if err != nil {
		logger.WithError(err).WithFields(log.Fields{
			"mount":     mount,
			"path":      path,
			"full_path": fullPath,
		}).Error("Failed to patch secret")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to patch secret: %v", err)), nil
	}

	successMsg := fmt.Sprintf("Successfully patched secret at path '%s' in mount '%s'", path, mount)

	if versionInfo != nil && versionInfo.Data != nil {
		successMsg = fmt.Sprintf("Successfully patched secret at path '%s' in mount '%s' (version %v)", path, mount, versionInfo.Data["version"])
	}

	logger.WithFields(log.Fields{
		"mount": mount,
		"path":  path,
	}).Info("Successfully patched secret")

	return mcp.NewToolResultText(successMsg), nil
}
