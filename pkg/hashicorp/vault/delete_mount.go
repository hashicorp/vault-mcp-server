// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
)

// DeleteMount creates a tool for deleting Vault mounts
func DeleteMount(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("delete_mount",
			mcp.WithDescription("Delete a mounted secret engine in Vault. Use with extreme caution as this will remove all data under the mount path!"),
			mcp.WithString("path", mcp.Required(), mcp.Description("The path where of mount to be deleted. Examples would be 'secrets' or 'kv'.")),
			mcp.WithString("namespace", mcp.Description("The namespace where the mount will be deleted.")),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return deleteMountHandler(ctx, req, logger)
		},
	}
}

func deleteMountHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling delete_mount request")

	// Extract parameters
	var path, namespace string

	if req.Params.Arguments != nil {
		if args, ok := req.Params.Arguments.(map[string]interface{}); ok {
			if path, ok = args["path"].(string); !ok || path == "" {
				return mcp.NewToolResultError("Missing or invalid 'path' parameter"), nil
			}

			namespace, _ = args["namespace"].(string)
		} else {
			return mcp.NewToolResultError("Invalid arguments format"), nil
		}
	} else {
		return mcp.NewToolResultError("Missing arguments"), nil
	}

	logger.WithFields(log.Fields{
		"path":      path,
		"namespace": namespace,
	}).Debug("Deleting mount")

	// Get Vault client from context
	client, err := GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	// Set the namespace on the client
	if namespace != "" {
		client = client.WithNamespace(namespace)
		logger.WithField("namespace", namespace).Debug("Set namespace on Vault client")
	}

	// Delete the mount
	err = client.Sys().Unmount(path)
	if err != nil {
		logger.WithError(err).WithField("path", path).Error("Failed to delete mount")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to delete mount at path '%s': %v", path, err)), nil
	}

	successMsg := fmt.Sprintf("Successfully deleted mount at path '%s'", path)
	logger.WithFields(log.Fields{
		"path":      path,
		"namespace": namespace,
	}).Info("Successfully deleted mount")

	return mcp.NewToolResultText(successMsg), nil
}
