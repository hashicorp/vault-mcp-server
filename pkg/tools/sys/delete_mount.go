// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package sys

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault-mcp-server/pkg/client"
	"github.com/hashicorp/vault-mcp-server/pkg/utils"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
)

// DeleteMount creates a tool for deleting Vault mounts
func DeleteMount(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("delete_mount",
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					DestructiveHint: utils.ToBoolPtr(true),
					IdempotentHint:  utils.ToBoolPtr(true),
				},
			),
			mcp.WithDescription("Delete a mounted secret engine in Vault. Use with extreme caution as this will remove all data under the mount path!"),
			mcp.WithString("path",
				mcp.Required(),
				mcp.Description("The path where of mount to be deleted. Examples would be 'secrets' or 'kv'."),
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return deleteMountHandler(ctx, req, logger)
		},
	}
}

func deleteMountHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling delete_mount request")

	// Extract parameters
	var path string

	if req.Params.Arguments != nil {
		if args, ok := req.Params.Arguments.(map[string]interface{}); ok {
			if path, ok = args["path"].(string); !ok || path == "" {
				return mcp.NewToolResultError("Missing or invalid 'path' parameter"), nil
			}
		} else {
			return mcp.NewToolResultError("Invalid arguments format"), nil
		}
	} else {
		return mcp.NewToolResultError("Missing arguments"), nil
	}

	logger.WithField("path", path).Debug("Deleting mount")

	// Get Vault client from context
	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	// Delete the mount
	err = vault.Sys().Unmount(path)
	if err != nil {
		logger.WithError(err).WithField("path", path).Error("Failed to delete mount")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to delete mount at path '%s': %v", path, err)), nil
	}

	successMsg := fmt.Sprintf("Successfully deleted mount at path '%s'", path)
	logger.WithField("path", path).Info("Successfully deleted mount")

	return mcp.NewToolResultText(successMsg), nil
}
