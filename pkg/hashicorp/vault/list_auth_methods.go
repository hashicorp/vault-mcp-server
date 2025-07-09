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

// AuthMethod represents an authentication method in Vault
type AuthMethod struct {
	Name                  string            `json:"name"`
	Type                  string            `json:"type"`
	Description           string            `json:"description"`
	Accessor              string            `json:"accessor"`
	Local                 bool              `json:"local"`
	SealWrap              bool              `json:"seal_wrap"`
	ExternalEntropyAccess bool              `json:"external_entropy_access"`
	Config                *AuthMethodConfig `json:"config"`
	Options               map[string]string `json:"options"`
	UUID                  string            `json:"uuid"`
	PluginVersion         string            `json:"plugin_version"`
	RunningSha256         string            `json:"running_sha256"`
	DeprecationStatus     string            `json:"deprecation_status"`
}

// AuthMethodConfig represents the configuration of an auth method
type AuthMethodConfig struct {
	DefaultLeaseTTL int    `json:"default_lease_ttl"`
	MaxLeaseTTL     int    `json:"max_lease_ttl"`
	ForceNoCache    bool   `json:"force_no_cache"`
	TokenType       string `json:"token_type"`
}

// ListAuthMethods creates a tool for listing all enabled authentication methods in Vault
func ListAuthMethods(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("list_auth_methods",
			mcp.WithDescription("List all enabled authentication methods in Vault"),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return listAuthMethodsHandler(ctx, req, logger)
		},
	}
}

func listAuthMethodsHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling list_auth_methods request")

	// Get Vault client from context
	client, err := GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	// List auth methods from Vault
	authMethods, err := client.Sys().ListAuth()
	if err != nil {
		logger.WithError(err).Error("Failed to list auth methods")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to list auth methods: %v", err)), nil
	}

	var results []*AuthMethod
	for k, v := range authMethods {
		authMethod := &AuthMethod{
			Name:                  k,
			Type:                  v.Type,
			Description:           v.Description,
			Accessor:              v.Accessor,
			Local:                 v.Local,
			SealWrap:              v.SealWrap,
			ExternalEntropyAccess: v.ExternalEntropyAccess,
			Options:               v.Options,
			UUID:                  v.UUID,
			PluginVersion:         v.PluginVersion,
			RunningSha256:         v.RunningSha256,
			DeprecationStatus:     v.DeprecationStatus,
		}

		// MountConfigOutput is a struct, not a pointer, so it's always "non-nil"
		authMethod.Config = &AuthMethodConfig{
			DefaultLeaseTTL: v.Config.DefaultLeaseTTL,
			MaxLeaseTTL:     v.Config.MaxLeaseTTL,
			ForceNoCache:    v.Config.ForceNoCache,
			TokenType:       v.Config.TokenType,
		}

		results = append(results, authMethod)
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
