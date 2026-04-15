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

// ReadHostInfo creates a tool for reading Vault host information from sys/host-info.
func ReadHostInfo(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("read_host_info",
			mcp.WithDescription("Read detailed host information from Vault's sys/host-info endpoint, including OS, runtime, memory, CPU, and host-level characteristics useful for diagnostics and capacity analysis."),
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					IdempotentHint: utils.ToBoolPtr(true),
					ReadOnlyHint:   utils.ToBoolPtr(true),
				},
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return readHostInfoHandler(ctx, req, logger)
		},
	}
}

func readHostInfoHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling read_host_info request")

	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	secret, err := vault.Logical().Read("sys/host-info")
	if err != nil {
		logger.WithError(err).Error("Failed to read host info")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to read host info: %v", err)), nil
	}

	if secret == nil || secret.Data == nil {
		return mcp.NewToolResultError("No host info data returned"), nil
	}

	jsonData, err := json.MarshalIndent(secret.Data, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to format host info: %v", err)), nil
	}
	resultText := string(jsonData)

	logger.WithFields(log.Fields{
		"data_length": len(resultText),
	}).Debug("Successfully retrieved host info")

	return mcp.NewToolResultText(resultText), nil
}
