// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package pki

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault-mcp-server/pkg/client"
	"github.com/hashicorp/vault-mcp-server/pkg/utils"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
)

// DeletePkiRole deletes a tool for deleting pki roles
func DeletePkiRole(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("delete_pki_role",
			mcp.WithDescription("Delete a PKI SSL role in Vault."),
			mcp.WithString("mount",
				mcp.DefaultString("pki"),
				mcp.Description("The mount where the pki role will be deleted. Defaults to 'pki'."),
			),
			mcp.WithString("role_name",
				mcp.Required(),
				mcp.Description("The name of the role."),
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return deletePkiRoleHandler(ctx, req, logger)
		},
	}
}

func deletePkiRoleHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling delete_pki_role request")

	// Extract parameters
	args, ok := req.Params.Arguments.(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("Missing or invalid arguments format"), nil
	}

	mount, err := utils.ExtractMountPath(args)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	roleName, ok := args["role_name"].(string)
	if !ok || roleName == "" {
		return mcp.NewToolResultError("Missing or invalid 'role_name' parameter"), nil
	}

	logger.WithFields(log.Fields{
		"mount":     mount,
		"role_name": roleName,
	}).Debug("Deleting pki role with parameters")

	// Get Vault client from context
	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	mounts, err := vault.Sys().ListMounts()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to list mounts: %v", err)), nil
	}

	// Check if the mount exists
	if _, ok := mounts[mount+"/"]; !ok {
		return mcp.NewToolResultError(fmt.Sprintf("mount path '%s' does not exist, you should use 'enable_pki' if you want enable pki on this mount.", mount)), nil
	}

	fullPath := fmt.Sprintf("%s/roles/%s", mount, roleName)

	// Write the role data to the specified path
	_, err = vault.Logical().Delete(fullPath)

	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to write to path '%s': %v", fullPath, err)), nil
	}

	successMsg := fmt.Sprintf("Successfully deleted pki role with name '%s' on mount '%s'.", roleName, mount)

	logger.WithFields(log.Fields{
		"role_name": roleName,
	}).Info("Successfully deleted pki role")

	return mcp.NewToolResultText(successMsg), nil
}
