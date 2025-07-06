// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package tools

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault-mcp-server/pkg/vault"
	"github.com/hashicorp/vault/api"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
)

// createMount creates a tool for creating Vault mounts
func createMount(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("createMount",
			mcp.WithDescription("Create a new mount in Vault"),
			mcp.WithString("type", mcp.Required(), mcp.Description("The type of mount (e.g., 'kv', 'kv2')")),
			mcp.WithString("path", mcp.Required(), mcp.Description("The path where the mount will be created")),
			mcp.WithString("description", mcp.Description("Description for the mount")),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return createMountHandler(ctx, req, logger)
		},
	}
}

func createMountHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling createMount request")

	// Extract parameters
	var mountType, path, description string

	if req.Params.Arguments != nil {
		if args, ok := req.Params.Arguments.(map[string]interface{}); ok {
			if mountType, ok = args["type"].(string); !ok || mountType == "" {
				return mcp.NewToolResultError("Missing or invalid 'type' parameter"), nil
			}

			if path, ok = args["path"].(string); !ok || path == "" {
				return mcp.NewToolResultError("Missing or invalid 'path' parameter"), nil
			}

			description, _ = args["description"].(string)
		} else {
			return mcp.NewToolResultError("Invalid arguments format"), nil
		}
	} else {
		return mcp.NewToolResultError("Missing arguments"), nil
	}

	logger.WithFields(log.Fields{
		"type":        mountType,
		"path":        path,
		"description": description,
	}).Debug("Creating mount with parameters")

	// Get Vault client from context
	client, err := vault.GetVaultClientFromContext(ctx)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	// Prepare mount input
	mountInput := &api.MountInput{
		Type:        mountType,
		Description: description,
	}

	// Create the mount
	err = client.Sys().Mount(path, mountInput)
	if err != nil {
		logger.WithError(err).WithFields(log.Fields{
			"type": mountType,
			"path": path,
		}).Error("Failed to create mount")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to create mount: %v", err)), nil
	}

	successMsg := fmt.Sprintf("Successfully created %s mount at path '%s'", mountType, path)
	if description != "" {
		successMsg += fmt.Sprintf(" with description: %s", description)
	}

	logger.WithFields(log.Fields{
		"type": mountType,
		"path": path,
	}).Info("Successfully created mount")

	return mcp.NewToolResultText(successMsg), nil
}
