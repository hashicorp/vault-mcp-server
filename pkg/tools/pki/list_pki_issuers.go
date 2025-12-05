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

// ListPkiIssuers creates a tool for listing pki issuers
func ListPkiIssuers(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("list_pki_issuers",
			mcp.WithDescription("Get a list of PKI issuers on a specific pki mount in Vault, allowing you to see all the configured issuers for that mount."),
			mcp.WithString("mount",
				mcp.DefaultString("pki"),
				mcp.Description("The mount where the pki issuer will be listed. Defaults to 'pki'."),
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return listPkiIssuersHandler(ctx, req, logger)
		},
	}
}

func listPkiIssuersHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling list_pki_issuers request")

	// Extract parameters
	args, ok := req.Params.Arguments.(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("Missing or invalid arguments format"), nil
	}

	mount, err := utils.ExtractMountPath(args)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	logger.WithFields(log.Fields{
		"mount": mount,
	}).Debug("Listing pki issuers with parameters")

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

	fullPath := fmt.Sprintf("%s/issuers", mount)

	// Write the issuer data to the specified path
	secret, err := vault.Logical().List(fullPath)

	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to read path '%s': %v", fullPath, err)), nil
	}

	// V1 API structure: secret.Data directly contains the key-value pairs
	keyInfo := secret.Data["key_info"]

	// Marshal to JSON
	jsonData, err := json.Marshal(keyInfo)
	if err != nil {
		logger.WithError(err).Error("Failed to marshal secret to JSON")
		return mcp.NewToolResultError(fmt.Sprintf("Error marshaling JSON: %v", err)), nil
	}

	logger.WithFields(log.Fields{
		"mount": mount,
	}).Debug("Successfully read pki issuers")

	return mcp.NewToolResultText(string(jsonData)), nil
}
