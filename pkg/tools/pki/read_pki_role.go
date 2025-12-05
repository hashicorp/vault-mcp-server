// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package pki

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/hashicorp/vault-mcp-server/pkg/client"
	"github.com/hashicorp/vault-mcp-server/pkg/utils"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
)

// ReadPkiRole creates a tool for reading pki roles
func ReadPkiRole(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("read_pki_role",
			mcp.WithDescription("Read a PKI role details from a specific mount in Vault. This allows you to retrieve information about a specific PKI role."),
			mcp.WithString("mount",
				mcp.DefaultString("pki"),
				mcp.Description("The mount where the pki role will be created. Defaults to 'pki'."),
			),
			mcp.WithString("role_name",
				mcp.Required(),
				mcp.Description("The name of the role you want to retrieve. This name must correspond to a role_name in the data returned from the list_pki_roles function."),
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return readPkiRoleHandler(ctx, req, logger)
		},
	}
}

func readPkiRoleHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling read_pki_role request")

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
	}).Debug("Reading role details")

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

	// Read the secret
	secret, err := vault.Logical().Read(fullPath)
	if err != nil {
		logger.WithError(err).WithFields(log.Fields{
			"mount":     mount,
			"full_path": fullPath,
		}).Error("Failed to read role")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to read role: %v", err)), nil
	}

	if secret == nil {
		return mcp.NewToolResultError(fmt.Sprintf("No pki role found with name '%s' in mount '%s'", roleName, mount)), nil
	}

	secretData := secret.Data

	// Marshal to JSON
	jsonData, err := json.Marshal(secretData)
	if err != nil {
		logger.WithError(err).Error("Failed to marshal secret to JSON")
		return mcp.NewToolResultError(fmt.Sprintf("Error marshaling JSON: %v", err)), nil
	}

	logger.WithFields(log.Fields{
		"mount":     mount,
		"role_name": roleName,
	}).Debug("Successfully read role details")

	return mcp.NewToolResultText(string(jsonData)), nil
}
