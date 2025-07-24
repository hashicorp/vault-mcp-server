package vault

// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
)

// ParseVaultUIURLTool creates a tool for parsing Vault UI URLs to extract mount names, secret names, and policy names
func ParseVaultUIURLTool(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("parse_vault_ui_url",
			mcp.WithDescription("Parse a Vault UI URL to extract mount names, secret names, and policy names. Supports secrets URLs, list URLs, and policy URLs."),
			mcp.WithString("url", mcp.Required(), mcp.Description("The Vault UI URL to parse. Examples: 'http://localhost:4200/ui/vault/secrets/kv-random/kv/alpha', 'http://localhost:4200/ui/vault/secrets/kv-random/kv/list', 'http://localhost:4200/ui/vault/policy/acl/default'")),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return parseVaultUIURLHandler(ctx, req, logger)
		},
	}
}

func parseVaultUIURLHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling parse_vault_ui_url request")

	// Extract parameters
	var url string

	if req.Params.Arguments != nil {
		if args, ok := req.Params.Arguments.(map[string]interface{}); ok {
			if url, ok = args["url"].(string); !ok || url == "" {
				return mcp.NewToolResultError("Missing or invalid 'url' parameter"), nil
			}
		} else {
			return mcp.NewToolResultError("Invalid arguments format"), nil
		}
	} else {
		return mcp.NewToolResultError("Missing arguments"), nil
	}

	logger.WithField("url", url).Debug("Parsing Vault UI URL")

	// Parse the URL using the existing function
	components, err := ParseVaultUIURL(url)
	if err != nil {
		logger.WithError(err).WithField("url", url).Error("Failed to parse Vault UI URL")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to parse URL: %v", err)), nil
	}

	// Marshal the result to JSON
	jsonData, err := json.Marshal(components)
	if err != nil {
		logger.WithError(err).Error("Failed to marshal URL components to JSON")
		return mcp.NewToolResultError(fmt.Sprintf("Error marshaling JSON: %v", err)), nil
	}

	logger.WithFields(log.Fields{
		"url_type":    components.URLType,
		"mount_name":  components.MountName,
		"secret_name": components.SecretName,
		"policy_name": components.PolicyName,
	}).Debug("Successfully parsed Vault UI URL")

	return mcp.NewToolResultText(string(jsonData)), nil
}
