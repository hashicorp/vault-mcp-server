// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/api"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
)

// EnableAuthMethod creates a tool for enabling authentication methods in Vault
func EnableAuthMethod(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("enable_auth_method",
			mcp.WithDescription("Enable a new authentication method in Vault"),
			mcp.WithString("path", mcp.Required(), mcp.Description("The path where the auth method will be mounted. For example, 'github' or 'my-userpass'.")),
			mcp.WithString("type", mcp.Required(), mcp.Description("The type of authentication method. Examples: 'userpass', 'github', 'ldap', 'okta', 'aws', 'kubernetes'.")),
			mcp.WithString("description", mcp.DefaultString(""), mcp.Description("A human-friendly description of the auth method.")),
			mcp.WithString("local", mcp.DefaultString("false"), mcp.Description("Whether the auth method is local only (not replicated across clusters). Set to 'true' or 'false'.")),
			mcp.WithString("seal_wrap", mcp.DefaultString("false"), mcp.Description("Enable seal wrapping for the mount. Set to 'true' or 'false'.")),
			mcp.WithObject("config", mcp.Description("Configuration options for this auth method (e.g., default_lease_ttl, max_lease_ttl, token_type).")),
			mcp.WithObject("options", mcp.Description("Auth method-specific options.")),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return enableAuthMethodHandler(ctx, req, logger)
		},
	}
}

func enableAuthMethodHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling enable_auth_method request")

	// Extract parameters
	var path, authType, description, localStr, sealWrapStr string
	var config, options interface{}

	if req.Params.Arguments != nil {
		if args, ok := req.Params.Arguments.(map[string]interface{}); ok {
			if path, ok = args["path"].(string); !ok || path == "" {
				return mcp.NewToolResultError("Missing or invalid 'path' parameter"), nil
			}

			if authType, ok = args["type"].(string); !ok || authType == "" {
				return mcp.NewToolResultError("Missing or invalid 'type' parameter"), nil
			}

			description, _ = args["description"].(string)
			localStr, _ = args["local"].(string)
			sealWrapStr, _ = args["seal_wrap"].(string)
			config = args["config"]
			options = args["options"]

		} else {
			return mcp.NewToolResultError("Invalid arguments format"), nil
		}
	} else {
		return mcp.NewToolResultError("Missing arguments"), nil
	}

	// Convert string booleans to actual booleans
	local := localStr == "true"
	sealWrap := sealWrapStr == "true"

	logger.WithFields(log.Fields{
		"path":        path,
		"type":        authType,
		"description": description,
		"local":       local,
		"seal_wrap":   sealWrap,
	}).Debug("Enabling auth method with parameters")

	// Get Vault client from context
	client, err := GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	// Check if the auth method already exists
	authMethods, err := client.Sys().ListAuth()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to list auth methods: %v", err)), nil
	}

	// Check if the auth method exists at this path
	if _, ok := authMethods[path+"/"]; ok {
		return mcp.NewToolResultError(fmt.Sprintf("Auth method already exists at path '%s'. Use 'disable_auth_method' if you want to replace it.", path)), nil
	}

	// Prepare auth method input
	authMethodInput := &api.EnableAuthOptions{
		Type:        authType,
		Description: description,
		Local:       local,
		SealWrap:    sealWrap,
	}

	// Handle config if provided
	if config != nil {
		configInput := api.MountConfigInput{}
		if configMap, ok := config.(map[string]interface{}); ok {
			if defaultLeaseTTL, exists := configMap["default_lease_ttl"]; exists {
				if ttlStr, ok := defaultLeaseTTL.(string); ok {
					configInput.DefaultLeaseTTL = ttlStr
				}
			}
			if maxLeaseTTL, exists := configMap["max_lease_ttl"]; exists {
				if ttlStr, ok := maxLeaseTTL.(string); ok {
					configInput.MaxLeaseTTL = ttlStr
				}
			}
			if tokenType, exists := configMap["token_type"]; exists {
				if tokenTypeStr, ok := tokenType.(string); ok {
					configInput.TokenType = tokenTypeStr
				}
			}
		}
		authMethodInput.Config = configInput
	}

	// Handle options if provided
	if options != nil {
		authMethodInput.Options = make(map[string]string)
		if optionsMap, ok := options.(map[string]interface{}); ok {
			for key, value := range optionsMap {
				if s, ok := value.(string); ok {
					authMethodInput.Options[key] = s
				} else {
					authMethodInput.Options[key] = fmt.Sprintf("%v", value)
				}
			}
		}
	}

	// Enable the auth method
	err = client.Sys().EnableAuthWithOptions(path, authMethodInput)
	if err != nil {
		logger.WithError(err).WithFields(log.Fields{
			"path": path,
			"type": authType,
		}).Error("Failed to enable auth method")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to enable auth method: %v", err)), nil
	}

	successMsg := fmt.Sprintf("Successfully enabled %s auth method at path '%s'", authType, path)
	if description != "" {
		successMsg += fmt.Sprintf(" with description: %s", description)
	}

	logger.WithFields(log.Fields{
		"path": path,
		"type": authType,
	}).Info("Successfully enabled auth method")

	return mcp.NewToolResultText(successMsg), nil
}
