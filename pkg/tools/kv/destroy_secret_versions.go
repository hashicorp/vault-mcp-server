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

// DestroySecretVersions creates a tool for permanently destroying secret versions in a Vault KV v2 mount
func DestroySecretVersions(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("destroy_secret_versions",
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					DestructiveHint: utils.ToBoolPtr(true),
					IdempotentHint:  utils.ToBoolPtr(true),
				},
			),
			mcp.WithDescription("Permanently destroy specific versions of a secret in a KV v2 mount in Vault. Unlike delete, destroyed versions cannot be recovered. Only supported on KV v2 mounts."),
			mcp.WithString("mount",
				mcp.Required(),
				mcp.Description("The mount path of the secret engine."),
			),
			mcp.WithString("path",
				mcp.Required(),
				mcp.Description("The full path to the secret without the mount prefix."),
			),
			mcp.WithArray("versions",
				mcp.Required(),
				mcp.Description("An array of version numbers to permanently destroy. For example: [1, 3, 5]."),
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return destroySecretVersionsHandler(ctx, req, logger)
		},
	}
}

func destroySecretVersionsHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling destroy_secret_versions request")

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

	versionsRaw, ok := args["versions"].([]interface{})
	if !ok || len(versionsRaw) == 0 {
		return mcp.NewToolResultError("Missing or invalid 'versions' parameter — must be a non-empty array of version numbers"), nil
	}

	// Convert float64 values from JSON to int
	versions := make([]int, 0, len(versionsRaw))
	for _, v := range versionsRaw {
		vFloat, ok := v.(float64)
		if !ok {
			return mcp.NewToolResultError("Invalid version number in 'versions' array — each element must be a number"), nil
		}
		versions = append(versions, int(vFloat))
	}

	logger.WithFields(log.Fields{
		"mount":    mount,
		"path":     path,
		"versions": versions,
	}).Debug("Destroying secret versions")

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
		return mcp.NewToolResultError("destroy_secret_versions is only supported on KV v2 mounts"), nil
	}

	// Destroy at mount/destroy/path
	fullPath := fmt.Sprintf("%s/destroy/%s", mount, strings.TrimPrefix(path, "/"))
	_, err = vault.Logical().Write(fullPath, map[string]interface{}{
		"versions": versions,
	})
	if err != nil {
		logger.WithError(err).WithFields(log.Fields{
			"mount":     mount,
			"path":      path,
			"full_path": fullPath,
			"versions":  versions,
		}).Error("Failed to destroy secret versions")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to destroy secret versions: %v", err)), nil
	}

	logger.WithFields(log.Fields{
		"mount":    mount,
		"path":     path,
		"versions": versions,
	}).Info("Successfully destroyed secret versions")

	return mcp.NewToolResultText(fmt.Sprintf("Successfully destroyed versions %v of secret at path '%s' in mount '%s'", versions, path, mount)), nil
}
