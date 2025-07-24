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

// DisableAuthMethod creates a tool for disabling authentication methods in Vault
func DisableAuthMethod(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("disable_auth_method",
			mcp.WithDescription("Disable an authentication method in Vault. Use with caution as this will remove the auth method and all associated data!"),
			mcp.WithString("path", mcp.Required(), mcp.Description("The path of the auth method to disable. For example, 'github' or 'my-userpass'.")),
			mcp.WithString("namespace", mcp.Description("The namespace where the auth method will be disabled.")),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return disableAuthMethodHandler(ctx, req, logger)
		},
	}
}

func disableAuthMethodHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling disable_auth_method request")

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

	logger.WithField("path", path).Debug("Disabling auth method")

	// Get Vault client from context
	client, err := GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	// Check if the auth method exists
	authMethods, err := client.Sys().ListAuth()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to list auth methods: %v", err)), nil
	}

	// Check if the auth method exists at this path
	if _, ok := authMethods[path+"/"]; !ok {
		return mcp.NewToolResultError(fmt.Sprintf("Auth method does not exist at path '%s'", path)), nil
	}

	// Disable the auth method
	err = client.Sys().DisableAuth(path)
	if err != nil {
		logger.WithError(err).WithField("path", path).Error("Failed to disable auth method")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to disable auth method at path '%s': %v", path, err)), nil
	}

	successMsg := fmt.Sprintf("Successfully disabled auth method at path '%s'", path)
	logger.WithField("path", path).Info("Successfully disabled auth method")

	return mcp.NewToolResultText(successMsg), nil
}
