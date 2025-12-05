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

// ReadPkiIssuer creates a tool for reading pki issuers
func ReadPkiIssuer(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("read_pki_issuer",
			mcp.WithDescription("Read a PKI issuer details from a specific mount in Vault, allowing you to retrieve information about a specific PKI issuer."),
			mcp.WithString("mount",
				mcp.DefaultString("pki"),
				mcp.Description("The mount where the pki issuer will be created. Defaults to 'pki'."),
			),
			mcp.WithString("issuer_name",
				mcp.Required(),
				mcp.Description("The name of the issuer you want to retrieve. This name must correspond to an issuer_name in the data returned from the list_pki_issuers function."),
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return readPkiIssuerHandler(ctx, req, logger)
		},
	}
}

func readPkiIssuerHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling read_pki_issuer request")

	// Extract parameters
	args, ok := req.Params.Arguments.(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("Missing or invalid arguments format"), nil
	}

	mount, err := utils.ExtractMountPath(args)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	issuerName, ok := args["issuer_name"].(string)
	if !ok || issuerName == "" {
		return mcp.NewToolResultError("Missing or invalid 'issuer_name' parameter"), nil
	}

	logger.WithFields(log.Fields{
		"mount":       mount,
		"issuer_name": issuerName,
	}).Debug("Reading issuer details")

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
	keyInfo := secret.Data["key_info"].(map[string]interface{})

	var issuerId string

	for key, value := range keyInfo {
		if value.(map[string]interface{})["issuer_name"] == issuerName {
			issuerId = key
			break
		}
	}

	if issuerId == "" {
		return mcp.NewToolResultError(fmt.Sprintf("No issuer found with name '%s' in mount '%s'", issuerName, mount)), nil
	}

	fullPath = fmt.Sprintf("%s/issuer/%s", mount, issuerId)

	// Read the secret
	secret, err = vault.Logical().Read(fullPath)
	if err != nil {
		logger.WithError(err).WithFields(log.Fields{
			"mount":     mount,
			"full_path": fullPath,
		}).Error("Failed to read issuer")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to read issuer: %v", err)), nil
	}

	secretData := secret.Data

	// Marshal to JSON
	jsonData, err := json.Marshal(secretData)
	if err != nil {
		logger.WithError(err).Error("Failed to marshal secret to JSON")
		return mcp.NewToolResultError(fmt.Sprintf("Error marshaling JSON: %v", err)), nil
	}

	logger.WithFields(log.Fields{
		"mount":       mount,
		"issuer_name": issuerName,
		"issuer_id":   issuerId,
	}).Debug("Successfully read issuer details")

	return mcp.NewToolResultText(string(jsonData)), nil
}
