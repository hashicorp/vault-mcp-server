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

// IssuePkiCertificate creates a tool for issuing pki certificates
func IssuePkiCertificate(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("issue_pki_certificate",
			mcp.WithDescription("Create a new PKI SSL certificate issuer in Vault, allowing for the issuance of SSL/TLS certificates."),
			mcp.WithString("mount",
				mcp.DefaultString("pki"),
				mcp.Description("The mount where the pki issuer will be created. Defaults to 'pki'."),
			),
			mcp.WithString("role_name",
				mcp.Required(),
				mcp.Description("The name of the role you want to use to generate the certificate. This name must correspond to a role_name in the data returned from the list_pki_roles function."),
			),
			mcp.WithString("common_name",
				mcp.Required(),
				mcp.Description("Common Name (CN) for the PKI certificate. This is typically the name of the organization or entity that the certificates will be issued for. Examples would be example.com or My Company."),
			),
			mcp.WithString("ttl",
				mcp.DefaultString("30d"),
				mcp.Description("Optional TTL for the certificate. This is the time that the certificate will be valid for. Defaults to '30d' (30 days). Other formats are also accepted, such as '87600h' for 10 years."),
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return issuePkiCertificateHandler(ctx, req, logger)
		},
	}
}

func issuePkiCertificateHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling issue_pki_certificate request")

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

	commonName, ok := args["common_name"].(string)
	if !ok || commonName == "" {
		return mcp.NewToolResultError("Missing or invalid 'common_name' parameter"), nil
	}

	ttl, _ := args["ttl"].(string)

	logger.WithFields(log.Fields{
		"mount":       mount,
		"role_name":   roleName,
		"common_name": commonName,
		"ttl":         ttl,
	}).Debug("Creating certificate with parameters")

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

	fullPath := fmt.Sprintf("%s/issue/%s", mount, roleName)

	requestData := map[string]interface{}{
		"common_name": commonName,
		"ttl":         ttl,
	}

	// Write the issuer data to the specified path
	secret, err := vault.Logical().Write(fullPath, requestData)

	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to write to path '%s': %v", fullPath, err)), nil
	}

	// V1 API structure: secret.Data directly contains the key-value pairs
	certificateData := secret.Data

	// Marshal to JSON
	jsonData, err := json.Marshal(certificateData)
	if err != nil {
		logger.WithError(err).Error("Failed to marshal secret to JSON")
		return mcp.NewToolResultError(fmt.Sprintf("Error marshaling JSON: %v", err)), nil
	}

	logger.WithFields(log.Fields{
		"role_name":   roleName,
		"common_name": commonName,
		"ttl":         ttl,
	}).Info("Successfully created pki certificate")

	return mcp.NewToolResultText(string(jsonData)), nil
}
