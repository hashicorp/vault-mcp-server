// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package sys

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hashicorp/vault-mcp-server/pkg/client"
	"github.com/hashicorp/vault-mcp-server/pkg/utils"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
)

type AuthMethodDetail struct {
	Path            string         `json:"path"`              // Path where the auth method is mounted
	Type            string         `json:"type"`              // Type of the auth method
	Description     string         `json:"description"`       // Description of the auth method
	Accessor        string         `json:"accessor"`          // Unique accessor for the auth method
	Local           bool           `json:"local"`             // Whether the auth method is local
	SealWrap        bool           `json:"seal_wrap"`         // Whether seal wrapping is enabled
	ExternalEntropy bool           `json:"external_entropy"`  // Whether external entropy is used
	Config          map[string]any `json:"config,omitempty"`  // Full configuration details
	Options         map[string]any `json:"options,omitempty"` // Auth method options
}

// ReadAuthMethod creates a tool for reading details of a specific auth method
func ReadAuthMethod(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("read_auth_method",
			mcp.WithDescription("Read detailed configuration and information about a specific authentication method in Vault. Returns full details including config, options, and metadata."),
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					IdempotentHint: utils.ToBoolPtr(true),
					ReadOnlyHint:   utils.ToBoolPtr(true),
				},
			),
			mcp.WithString("path",
				mcp.Required(),
				mcp.Description("The mount path of the auth method to read (e.g., 'approle/', 'userpass/', 'oidc/'). Include trailing slash.")),
			mcp.WithString("namespace",
				mcp.DefaultString(""),
				mcp.Description("Namespace path where the auth method exists (e.g., 'admin/' or empty for root). Defaults to current namespace.")),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return readAuthMethodHandler(ctx, req, logger)
		},
	}
}

func readAuthMethodHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling read_auth_method request")

	// Extract parameters
	args, ok := req.Params.Arguments.(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("Missing or invalid arguments format"), nil
	}

	path, ok := args["path"].(string)
	if !ok || path == "" {
		return mcp.NewToolResultError("Missing or invalid 'path' parameter"), nil
	}

	// Ensure path has trailing slash for consistency with Vault's API
	if !strings.HasSuffix(path, "/") {
		path = path + "/"
	}

	namespace, _ := args["namespace"].(string)

	logger.WithFields(log.Fields{
		"path":      path,
		"namespace": namespace,
	}).Debug("Reading auth method")

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

	// Read auth method from Vault
	auth, err := nsClient.Sys().ListAuth()
	if err != nil {
		logger.WithError(err).Error("Failed to list auth methods")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to read auth methods: %v", err)), nil
	}

	// Find the specific auth method by path
	authMethod, found := auth[path]
	if !found {
		logger.WithField("path", path).Warn("Auth method not found")
		return mcp.NewToolResultError(fmt.Sprintf("Auth method at path '%s' not found", path)), nil
	}

	// Build detailed response
	result := &AuthMethodDetail{
		Path:            path,
		Type:            authMethod.Type,
		Description:     authMethod.Description,
		Accessor:        authMethod.Accessor,
		Local:           authMethod.Local,
		SealWrap:        authMethod.SealWrap,
		ExternalEntropy: authMethod.ExternalEntropyAccess,
	}

	// Convert Options from map[string]string to map[string]any
	if authMethod.Options != nil {
		result.Options = make(map[string]any)
		for k, v := range authMethod.Options {
			result.Options[k] = v
		}
	}

	// Include full config details
	if authMethod.Config.DefaultLeaseTTL > 0 || authMethod.Config.MaxLeaseTTL > 0 {
		result.Config = map[string]any{
			"default_lease_ttl":            authMethod.Config.DefaultLeaseTTL,
			"max_lease_ttl":                authMethod.Config.MaxLeaseTTL,
			"force_no_cache":               authMethod.Config.ForceNoCache,
			"token_type":                   authMethod.Config.TokenType,
			"audit_non_hmac_request_keys":  authMethod.Config.AuditNonHMACRequestKeys,
			"audit_non_hmac_response_keys": authMethod.Config.AuditNonHMACResponseKeys,
			"listing_visibility":           authMethod.Config.ListingVisibility,
			"passthrough_request_headers":  authMethod.Config.PassthroughRequestHeaders,
			"allowed_response_headers":     authMethod.Config.AllowedResponseHeaders,
		}
	}

	// Marshal the struct to JSON
	jsonData, err := json.Marshal(result)
	if err != nil {
		logger.WithError(err).Error("Failed to marshal auth method to JSON")
		return mcp.NewToolResultError(fmt.Sprintf("Error marshaling JSON: %v", err)), nil
	}

	logger.WithField("path", path).Debug("Successfully read auth method")
	return mcp.NewToolResultText(string(jsonData)), nil
}
