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

// ReadAuthMethod creates a tool for reading authentication method configuration in Vault
func ReadAuthMethod(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("read_auth_method",
			mcp.WithDescription("Read the configuration of an authentication method in Vault"),
			mcp.WithString("path", mcp.Required(), mcp.Description("The path of the auth method to read. For example, 'github' or 'my-userpass'.")),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return readAuthMethodHandler(ctx, req, logger)
		},
	}
}

func readAuthMethodHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling read_auth_method request")

	// Extract parameters
	var path string

	if req.Params.Arguments != nil {
		if args, ok := req.Params.Arguments.(map[string]interface{}); ok {
			if path, ok = args["path"].(string); !ok || path == "" {
				return mcp.NewToolResultError("Missing or invalid 'path' parameter"), nil
			}
		} else {
			return mcp.NewToolResultError("Invalid arguments format"), nil
		}
	} else {
		return mcp.NewToolResultError("Missing arguments"), nil
	}

	logger.WithField("path", path).Debug("Reading auth method configuration")

	// Get Vault client from context
	client, err := GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	// Get the auth method configuration
	authMethods, err := client.Sys().ListAuth()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to list auth methods: %v", err)), nil
	}

	// Check if the auth method exists at this path
	authMethod, ok := authMethods[path+"/"]
	if !ok {
		return mcp.NewToolResultError(fmt.Sprintf("Auth method does not exist at path '%s'", path)), nil
	}

	// Convert to our auth method structure
	result := &AuthMethod{
		Name:                  path + "/",
		Type:                  authMethod.Type,
		Description:           authMethod.Description,
		Accessor:              authMethod.Accessor,
		Local:                 authMethod.Local,
		SealWrap:              authMethod.SealWrap,
		ExternalEntropyAccess: authMethod.ExternalEntropyAccess,
		Options:               authMethod.Options,
		UUID:                  authMethod.UUID,
		PluginVersion:         authMethod.PluginVersion,
		RunningSha256:         authMethod.RunningSha256,
		DeprecationStatus:     authMethod.DeprecationStatus,
		Config: &AuthMethodConfig{
			DefaultLeaseTTL: authMethod.Config.DefaultLeaseTTL,
			MaxLeaseTTL:     authMethod.Config.MaxLeaseTTL,
			ForceNoCache:    authMethod.Config.ForceNoCache,
			TokenType:       authMethod.Config.TokenType,
		},
	}

	// Marshal to JSON
	jsonData, err := json.Marshal(result)
	if err != nil {
		logger.WithError(err).Error("Failed to marshal auth method to JSON")
		return mcp.NewToolResultError(fmt.Sprintf("Error marshaling JSON: %v", err)), nil
	}

	logger.WithField("path", path).Debug("Successfully read auth method configuration")
	return mcp.NewToolResultText(string(jsonData)), nil
}
