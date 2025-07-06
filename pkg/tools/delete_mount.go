// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package tools

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault-mcp-server/pkg/vault"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
)

// deleteMount creates a tool for deleting Vault mounts
func deleteMount(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("deleteMount",
			mcp.WithDescription("Delete a mount in Vault"),
			mcp.WithString("path", mcp.Required(), mcp.Description("The path to the mount to be deleted")),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return deleteMountHandler(ctx, req, logger)
		},
	}
}

func deleteMountHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling deleteMount request")

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
	client, err := vault.GetVaultClientFromContext(ctx)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	// Delete the mount
	err = client.Sys().Unmount(path)
	if err != nil {
		logger.WithError(err).WithField("path", path).Error("Failed to delete mount")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to delete mount at path '%s': %v", path, err)), nil
	}

	successMsg := fmt.Sprintf("Successfully deleted mount at path '%s'", path)
	logger.WithField("path", path).Info("Successfully deleted mount")

	return mcp.NewToolResultText(successMsg), nil
}
