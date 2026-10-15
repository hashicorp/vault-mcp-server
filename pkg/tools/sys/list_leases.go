// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package sys

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

// ListLeases creates a tool for listing leases in Vault
func ListLeases(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("list_leases",
			mcp.WithDescription("List leases in Vault at a specific prefix path. Returns keys/paths containing leases. Omit prefix to list top-level lease paths. Use this to discover what lease paths exist before reading specific lease details. Useful for exploring lease hierarchy and finding active leases."),
			mcp.WithString("prefix",
				mcp.Description("Lease path prefix to list under (e.g., 'database/creds', 'pki/issue'). Omit to list top-level lease paths. The prefix determines which lease subtree to explore."),
			),
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					IdempotentHint: utils.ToBoolPtr(true),
					ReadOnlyHint:   utils.ToBoolPtr(true),
				},
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return listLeasesHandler(ctx, req, logger)
		},
	}
}

func listLeasesHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling list_leases request")

	// Extract parameters
	args, ok := req.Params.Arguments.(map[string]interface{})
	if !ok {
		args = make(map[string]interface{})
	}

	// Extract optional prefix parameter
	prefix := ""
	if prefixVal, ok := args["prefix"].(string); ok {
		prefix = prefixVal
	}

	logger.WithFields(log.Fields{
		"prefix": prefix,
	}).Debug("Listing Vault leases")

	// Get Vault client from context
	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	// Build the path
	path := "sys/leases/lookup"
	if prefix != "" {
		path = fmt.Sprintf("sys/leases/lookup/%s", prefix)
	}

	// List leases at the specified path
	secret, err := vault.Logical().List(path)
	if err != nil {
		logger.WithError(err).Error("Failed to list leases")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to list leases: %v", err)), nil
	}

	if secret == nil || secret.Data == nil {
		// No leases at this path
		return mcp.NewToolResultText("No leases found at this path"), nil
	}

	// Format the response
	jsonData, err := json.MarshalIndent(secret.Data, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to format lease list: %v", err)), nil
	}

	resultText := string(jsonData)

	logger.WithFields(log.Fields{
		"prefix":      prefix,
		"data_length": len(resultText),
	}).Debug("Successfully listed leases")

	return mcp.NewToolResultText(resultText), nil
}
