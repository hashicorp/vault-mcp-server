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

// DeletePolicy creates a tool for deleting ACL policies from Vault
func DeletePolicy(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("delete_policy",
			mcp.WithDescription("Delete an ACL policy from Vault"),
			mcp.WithString("name", mcp.Required(), mcp.Description("The name of the policy to delete")),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return deletePolicyHandler(ctx, req, logger)
		},
	}
}

func deletePolicyHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling delete_policy request")

	// Extract parameters
	var name string

	if req.Params.Arguments != nil {
		if args, ok := req.Params.Arguments.(map[string]interface{}); ok {
			if name, ok = args["name"].(string); !ok || name == "" {
				return mcp.NewToolResultError("Missing or invalid 'name' parameter"), nil
			}
		} else {
			return mcp.NewToolResultError("Invalid arguments format"), nil
		}
	} else {
		return mcp.NewToolResultError("Missing arguments"), nil
	}

	// Prevent deletion of default policies
	if name == "root" || name == "default" {
		return mcp.NewToolResultError(fmt.Sprintf("Cannot delete system policy '%s'", name)), nil
	}

	logger.WithField("policy_name", name).Debug("Deleting policy")

	// Get Vault client from context
	client, err := GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	// Delete the policy
	err = client.Sys().DeletePolicy(name)
	if err != nil {
		logger.WithError(err).WithField("policy_name", name).Error("Failed to delete policy")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to delete policy '%s': %v", name, err)), nil
	}

	successMsg := fmt.Sprintf("Successfully deleted policy '%s'", name)
	logger.WithField("policy_name", name).Info("Policy deleted successfully")

	return mcp.NewToolResultText(successMsg), nil
}
