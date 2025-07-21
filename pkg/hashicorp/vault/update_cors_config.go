// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
)

// UpdateCORSConfig creates a tool for updating CORS configuration in Vault
func UpdateCORSConfig(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("update_cors_config",
			mcp.WithDescription("Update CORS configuration in Vault"),
			mcp.WithString("enable", mcp.DefaultString(""), mcp.Description("Whether to enable CORS ('true' or 'false')")),
			mcp.WithString("allowed_origins", mcp.DefaultString(""), mcp.Description("Comma-separated list of allowed origins (e.g., 'https://example.com,https://app.example.com')")),
			mcp.WithString("allowed_headers", mcp.DefaultString(""), mcp.Description("Comma-separated list of allowed headers (e.g., 'Content-Type,Authorization')")),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return updateCORSConfigHandler(ctx, req, logger)
		},
	}
}

func updateCORSConfigHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling update_cors_config request")

	// Extract parameters
	var enable, allowedOrigins, allowedHeaders string

	if req.Params.Arguments != nil {
		if args, ok := req.Params.Arguments.(map[string]interface{}); ok {
			enable, _ = args["enable"].(string)
			allowedOrigins, _ = args["allowed_origins"].(string)
			allowedHeaders, _ = args["allowed_headers"].(string)
		} else {
			return mcp.NewToolResultError("Invalid arguments format"), nil
		}
	}

	// Validate at least one parameter is provided
	if enable == "" && allowedOrigins == "" && allowedHeaders == "" {
		return mcp.NewToolResultError("At least one configuration parameter must be provided"), nil
	}

	logger.WithFields(log.Fields{
		"enable":          enable,
		"allowed_origins": allowedOrigins,
		"allowed_headers": allowedHeaders,
	}).Debug("Updating CORS configuration")

	// Get Vault client from context
	client, err := GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	// Prepare the CORS configuration data
	configData := make(map[string]interface{})

	if enable != "" {
		if enable == "true" {
			configData["enabled"] = true
		} else if enable == "false" {
			configData["enabled"] = false
		} else {
			return mcp.NewToolResultError("Invalid 'enable' parameter. Must be 'true' or 'false'"), nil
		}
	}

	if allowedOrigins != "" {
		origins := strings.Split(allowedOrigins, ",")
		// Trim whitespace from each origin
		for i, origin := range origins {
			origins[i] = strings.TrimSpace(origin)
		}
		configData["allowed_origins"] = origins
	}

	if allowedHeaders != "" {
		headers := strings.Split(allowedHeaders, ",")
		// Trim whitespace from each header
		for i, header := range headers {
			headers[i] = strings.TrimSpace(header)
		}
		configData["allowed_headers"] = headers
	}

	// Write the CORS configuration
	_, err = client.Logical().Write("sys/config/cors", configData)
	if err != nil {
		logger.WithError(err).Error("Failed to update CORS configuration")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to update CORS configuration: %v", err)), nil
	}

	successMsg := "Successfully updated CORS configuration"
	logger.Info("CORS configuration updated successfully")

	return mcp.NewToolResultText(successMsg), nil
}
