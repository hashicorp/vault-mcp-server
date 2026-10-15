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

// ReadLease creates a tool for reading detailed information about a specific lease
func ReadLease(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("read_lease",
			mcp.WithDescription("Read detailed information about a specific Vault lease by lease ID. Returns lease metadata including issue time, expire time, TTL, renewable status, and associated secret data. Use this to inspect individual lease details, check expiration times, or troubleshoot lease-related issues."),
			mcp.WithString("lease_id",
				mcp.Required(),
				mcp.Description("The lease ID to retrieve details for (e.g., 'database/creds/readonly/abc123', 'pki/issue/server-cert/xyz789'). This is the complete lease identifier returned when a secret with a lease is created."),
			),
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					IdempotentHint: utils.ToBoolPtr(true),
					ReadOnlyHint:   utils.ToBoolPtr(true),
				},
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return readLeaseHandler(ctx, req, logger)
		},
	}
}

func readLeaseHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling read_lease request")

	// Extract parameters
	args, ok := req.Params.Arguments.(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("Missing or invalid arguments format"), nil
	}

	// Extract required lease_id parameter
	leaseID, ok := args["lease_id"].(string)
	if !ok || leaseID == "" {
		return mcp.NewToolResultError("lease_id is required"), nil
	}

	logger.WithFields(log.Fields{
		"lease_id": leaseID,
	}).Debug("Reading Vault lease details")

	// Get Vault client from context
	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	// Write to sys/leases/lookup with the lease_id in the payload
	data := map[string]interface{}{
		"lease_id": leaseID,
	}

	secret, err := vault.Logical().Write("sys/leases/lookup", data)
	if err != nil {
		logger.WithError(err).Error("Failed to read lease details")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to read lease details: %v", err)), nil
	}

	if secret == nil || secret.Data == nil {
		return mcp.NewToolResultError("Lease not found or no data returned"), nil
	}

	// Format the response
	jsonData, err := json.MarshalIndent(secret.Data, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to format lease details: %v", err)), nil
	}

	resultText := string(jsonData)

	logger.WithFields(log.Fields{
		"lease_id":    leaseID,
		"data_length": len(resultText),
	}).Debug("Successfully read lease details")

	return mcp.NewToolResultText(resultText), nil
}
