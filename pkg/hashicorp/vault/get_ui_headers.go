// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
)

// GetUIHeaders creates a tool for getting UI headers configuration from Vault
func GetUIHeaders(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("get_ui_headers",
			mcp.WithDescription("Get custom UI headers configuration for environment identification"),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return getUIHeadersHandler(ctx, req, logger)
		},
	}
}

func getUIHeadersHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling get_ui_headers request")

	// Get Vault client from context
	client, err := GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	// Try to read UI headers configuration
	// Note: This endpoint may not be available in all Vault versions
	path := "sys/config/ui/headers"
	secret, err := client.Logical().Read(path)
	if err != nil {
		logger.WithError(err).Error("Failed to read UI headers configuration")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to read UI headers: %v", err)), nil
	}

	var headers map[string]string
	if secret != nil && secret.Data != nil {
		headers = make(map[string]string)
		for key, value := range secret.Data {
			if strVal, ok := value.(string); ok {
				headers[key] = strVal
			} else {
				headers[key] = fmt.Sprintf("%v", value)
			}
		}
	} else {
		// No headers configured
		headers = make(map[string]string)
	}

	// Marshal to JSON
	jsonData, err := json.Marshal(headers)
	if err != nil {
		logger.WithError(err).Error("Failed to marshal UI headers to JSON")
		return mcp.NewToolResultError(fmt.Sprintf("Error marshaling JSON: %v", err)), nil
	}

	logger.WithField("header_count", len(headers)).Debug("Successfully retrieved UI headers")
	return mcp.NewToolResultText(string(jsonData)), nil
}
