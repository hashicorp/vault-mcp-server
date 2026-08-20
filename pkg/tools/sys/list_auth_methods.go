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

type AuthMethod struct {
	Path            string `json:"path"`              // Path where the auth method is mounted
	Type            string `json:"type"`              // Type of the auth method (e.g., userpass, approle, oidc)
	Description     string `json:"description"`       // Description of the auth method
	Accessor        string `json:"accessor"`          // Unique accessor for the auth method
	Local           bool   `json:"local"`             // Whether the auth method is local to the namespace
	SealWrap        bool   `json:"seal_wrap"`         // Whether seal wrapping is enabled
	ExternalEntropy bool   `json:"external_entropy"`  // Whether external entropy is used
	DefaultLeaseTTL int    `json:"default_lease_ttl"` // Default lease TTL
	MaxLeaseTTL     int    `json:"max_lease_ttl"`     // Max lease TTL
}

// ListAuthMethods creates a tool for listing Vault auth methods
func ListAuthMethods(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("list_auth_methods",
			mcp.WithDescription("List all enabled authentication methods in Vault. Returns information about each auth method including type, path, and configuration."),
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					IdempotentHint: utils.ToBoolPtr(true),
					ReadOnlyHint:   utils.ToBoolPtr(true),
				},
			),
			mcp.WithString("namespace",
				mcp.DefaultString(""),
				mcp.Description("Namespace path to list auth methods from (e.g., 'admin/' or empty for root). Defaults to current namespace.")),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return listAuthMethodsHandler(ctx, req, logger)
		},
	}
}

func listAuthMethodsHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling list_auth_methods request")

	// Extract parameters
	args, ok := req.Params.Arguments.(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("Missing or invalid arguments format"), nil
	}

	namespace, _ := args["namespace"].(string)

	logger.WithFields(log.Fields{
		"namespace": namespace,
	}).Debug("Listing auth methods")

	// Get Vault client from context
	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	// Create a new client instance with the specified namespace if provided
	nsClient := vault
	if namespace != "" {
		nsClient = vault.WithNamespace(namespace)
		logger.WithField("namespace", namespace).Debug("Using specified namespace")
	}

	// List auth methods from Vault
	auths, err := nsClient.Sys().ListAuth()
	if err != nil {
		logger.WithError(err).Error("Failed to list auth methods")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to list auth methods: %v", err)), nil
	}

	var results []*AuthMethod
	for path, auth := range auths {
		method := &AuthMethod{
			Path:            path,
			Type:            auth.Type,
			Description:     auth.Description,
			Accessor:        auth.Accessor,
			Local:           auth.Local,
			SealWrap:        auth.SealWrap,
			ExternalEntropy: auth.ExternalEntropyAccess,
			DefaultLeaseTTL: auth.Config.DefaultLeaseTTL,
			MaxLeaseTTL:     auth.Config.MaxLeaseTTL,
		}
		results = append(results, method)
	}

	// Marshal the struct to JSON
	jsonData, err := json.Marshal(results)
	if err != nil {
		logger.WithError(err).Error("Failed to marshal auth methods to JSON")
		return mcp.NewToolResultError(fmt.Sprintf("Error marshaling JSON: %v", err)), nil
	}

	logger.WithField("auth_method_count", len(results)).Debug("Successfully listed auth methods")
	return mcp.NewToolResultText(string(jsonData)), nil
}
