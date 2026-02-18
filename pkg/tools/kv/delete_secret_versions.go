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

// DeleteSecretVersions creates a tool for soft-deleting specific versions of a secret in a Vault KV v2 mount
func DeleteSecretVersions(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("delete_secret_versions",
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					DestructiveHint: utils.ToBoolPtr(true),
					IdempotentHint:  utils.ToBoolPtr(true),
				},
			),
			mcp.WithDescription("Soft-delete specific versions of a secret in a KV v2 mount in Vault. The secret data is marked as deleted but can be recovered using undelete_secret. Only supported on KV v2 mounts."),
			mcp.WithString("mount",
				mcp.Required(),
				mcp.Description("The mount path of the secret engine."),
			),
			mcp.WithString("path",
				mcp.Required(),
				mcp.Description("The full path to the secret without the mount prefix."),
			),
			mcp.WithArray("versions",
				mcp.Description("An array of version numbers to soft-delete. For example: [1, 3, 5]. If not specified, the latest version is soft-deleted. Soft-deleted versions can be recovered with undelete_secret."),
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return deleteSecretVersionsHandler(ctx, req, logger)
		},
	}
}

func deleteSecretVersionsHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling delete_secret_versions request")

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
		return mcp.NewToolResultError("delete_secret_versions is only supported on KV v2 mounts"), nil
	}

	versionsRaw, hasVersions := args["versions"].([]interface{})

	if hasVersions && len(versionsRaw) > 0 {
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
		}).Debug("Soft-deleting secret versions")

		// Soft-delete specific versions at mount/delete/path
		fullPath := fmt.Sprintf("%s/delete/%s", mount, strings.TrimPrefix(path, "/"))
		_, err = vault.Logical().Write(fullPath, map[string]interface{}{
			"versions": versions,
		})
		if err != nil {
			logger.WithError(err).WithFields(log.Fields{
				"mount":     mount,
				"path":      path,
				"full_path": fullPath,
				"versions":  versions,
			}).Error("Failed to soft-delete secret versions")
			return mcp.NewToolResultError(fmt.Sprintf("Failed to soft-delete secret versions: %v", err)), nil
		}

		logger.WithFields(log.Fields{
			"mount":    mount,
			"path":     path,
			"versions": versions,
		}).Info("Successfully soft-deleted secret versions")

		return mcp.NewToolResultText(fmt.Sprintf("Successfully soft-deleted versions %v of secret at path '%s' in mount '%s'. Use undelete_secret to recover them.", versions, path, mount)), nil
	}

	// No versions specified: DELETE on the data path soft-deletes the latest version
	logger.WithFields(log.Fields{
		"mount": mount,
		"path":  path,
	}).Debug("Soft-deleting latest secret version")

	dataPath := fmt.Sprintf("%s/data/%s", mount, strings.TrimPrefix(path, "/"))
	_, err = vault.Logical().Delete(dataPath)
	if err != nil {
		logger.WithError(err).WithFields(log.Fields{
			"mount":     mount,
			"path":      path,
			"full_path": dataPath,
		}).Error("Failed to soft-delete latest secret version")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to soft-delete latest secret version: %v", err)), nil
	}

	logger.WithFields(log.Fields{
		"mount": mount,
		"path":  path,
	}).Info("Successfully soft-deleted latest secret version")

	return mcp.NewToolResultText(fmt.Sprintf("Successfully soft-deleted the latest version of secret at path '%s' in mount '%s'. Use undelete_secret to recover it.", path, mount)), nil
}