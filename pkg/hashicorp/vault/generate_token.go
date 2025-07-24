// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
)

// TokenResponse represents a generated token response
type TokenResponse struct {
	Token          string            `json:"token"`
	TokenAccessor  string            `json:"token_accessor"`
	Policies       []string          `json:"policies"`
	EntityID       string            `json:"entity_id,omitempty"`
	Orphan         bool              `json:"orphan"`
	Renewable      bool              `json:"renewable"`
	LeaseDuration  int               `json:"lease_duration"`
	TTL            int               `json:"ttl"`
	ExplicitMaxTTL int               `json:"explicit_max_ttl"`
	Metadata       map[string]string `json:"metadata,omitempty"`
	NumUses        int               `json:"num_uses"`
	DisplayName    string            `json:"display_name,omitempty"`
	CreationTime   string            `json:"creation_time"`
	Namespace      string            `json:"namespace,omitempty"`
}

// GenerateToken creates a tool for generating Vault tokens with specific policies and namespaces
func GenerateToken(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("generate_token",
			mcp.WithDescription("Generate a new Vault token with specified policies and optional namespace. This token can be used to authenticate with Vault APIs."),
			mcp.WithString("policies", mcp.Description("Comma-separated list of policies to attach to the token (e.g., 'policy1,policy2'). If not specified, the token will inherit the policies of the current token.")),
			mcp.WithString("namespace", mcp.Description("The namespace where the token will be created and scoped to.")),
			mcp.WithString("ttl", mcp.Description("Time-to-live for the token (e.g., '1h', '24h', '30d'). Defaults to the auth method's default TTL.")),
			mcp.WithString("max_ttl", mcp.Description("Maximum time-to-live for the token (e.g., '24h', '168h'). Cannot exceed the auth method's max TTL.")),
			mcp.WithString("display_name", mcp.Description("A human-readable display name for the token.")),
			mcp.WithString("num_uses", mcp.Description("Number of times this token can be used. Set to 0 for unlimited uses (default).")),
			mcp.WithBoolean("orphan", mcp.DefaultBool(false), mcp.Description("Create an orphan token that will not be revoked when the parent token is revoked.")),
			mcp.WithBoolean("renewable", mcp.DefaultBool(true), mcp.Description("Whether the token can be renewed to extend its TTL.")),
			mcp.WithObject("metadata", mcp.Description("Key-value metadata to associate with the token (as JSON object).")),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return generateTokenHandler(ctx, req, logger)
		},
	}
}

func generateTokenHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling generate_token request")

	// Extract parameters
	var policies, namespace, ttl, maxTTL, displayName, numUsesStr string
	var orphan, renewable bool
	var metadata map[string]interface{}

	if req.Params.Arguments != nil {
		if args, ok := req.Params.Arguments.(map[string]interface{}); ok {
			policies, _ = args["policies"].(string)
			namespace, _ = args["namespace"].(string)
			ttl, _ = args["ttl"].(string)
			maxTTL, _ = args["max_ttl"].(string)
			displayName, _ = args["display_name"].(string)
			numUsesStr, _ = args["num_uses"].(string)

			if val, exists := args["orphan"]; exists {
				if b, ok := val.(bool); ok {
					orphan = b
				}
			}

			if val, exists := args["renewable"]; exists {
				if b, ok := val.(bool); ok {
					renewable = b
				}
			} else {
				renewable = true // default to true
			}

			if val, exists := args["metadata"]; exists {
				if m, ok := val.(map[string]interface{}); ok {
					metadata = m
				}
			}
		}
	}

	logger.WithFields(log.Fields{
		"policies":     policies,
		"namespace":    namespace,
		"ttl":          ttl,
		"max_ttl":      maxTTL,
		"display_name": displayName,
		"num_uses":     numUsesStr,
		"orphan":       orphan,
		"renewable":    renewable,
	}).Debug("Generating token with parameters")

	// Get Vault client from context
	client, err := GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	// Set the namespace on the client
	if namespace != "" {
		client = client.WithNamespace(namespace)
		logger.WithField("namespace", namespace).Debug("Set namespace on Vault client")
	}

	// Prepare token creation request data
	data := make(map[string]interface{})

	// Parse policies
	if policies != "" {
		policyList := strings.Split(policies, ",")
		for i, policy := range policyList {
			policyList[i] = strings.TrimSpace(policy)
		}
		data["policies"] = policyList
	}

	// Set TTL if provided
	if ttl != "" {
		data["ttl"] = ttl
	}

	// Set max TTL if provided
	if maxTTL != "" {
		data["explicit_max_ttl"] = maxTTL
	}

	// Set display name if provided
	if displayName != "" {
		data["display_name"] = displayName
	}

	// Parse and set number of uses
	if numUsesStr != "" {
		numUses, err := strconv.Atoi(numUsesStr)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Invalid num_uses value '%s': %v", numUsesStr, err)), nil
		}
		data["num_uses"] = numUses
	}

	// Set orphan flag
	data["no_parent"] = orphan

	// Set renewable flag
	data["renewable"] = renewable

	// Set metadata if provided
	if metadata != nil {
		// Convert metadata to string-string map as required by Vault
		metadataMap := make(map[string]string)
		for k, v := range metadata {
			if str, ok := v.(string); ok {
				metadataMap[k] = str
			} else {
				metadataMap[k] = fmt.Sprintf("%v", v)
			}
		}
		data["meta"] = metadataMap
	}

	// Create the token
	secret, err := client.Logical().Write("auth/token/create", data)
	if err != nil {
		logger.WithError(err).Error("Failed to generate token")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to generate token: %v", err)), nil
	}

	if secret == nil || secret.Auth == nil {
		logger.Error("No token returned from Vault")
		return mcp.NewToolResultError("No token returned from Vault"), nil
	}

	// Construct the response
	response := &TokenResponse{
		Token:          secret.Auth.ClientToken,
		TokenAccessor:  secret.Auth.Accessor,
		Policies:       secret.Auth.Policies,
		EntityID:       secret.Auth.EntityID,
		Orphan:         secret.Auth.Orphan,
		Renewable:      secret.Auth.Renewable,
		LeaseDuration:  secret.Auth.LeaseDuration,
		TTL:            secret.Auth.LeaseDuration, // TTL is the same as lease duration
		ExplicitMaxTTL: secret.Auth.LeaseDuration, // This might need adjustment based on response
		Metadata:       secret.Auth.Metadata,
		DisplayName:    displayName, // Use the input display name
		CreationTime:   "",          // Will be set separately if available in secret.Data
		Namespace:      namespace,
	}

	// Try to extract additional information from secret.Data if available
	if secret.Data != nil {
		if creationTime, ok := secret.Data["creation_time"]; ok {
			response.CreationTime = fmt.Sprintf("%v", creationTime)
		}
		if explicitMaxTTL, ok := secret.Data["explicit_max_ttl"]; ok {
			if maxTTLInt, ok := explicitMaxTTL.(int); ok {
				response.ExplicitMaxTTL = maxTTLInt
			}
		}
	}

	// If num_uses was set, include it in response
	if numUsesStr != "" {
		if numUses, err := strconv.Atoi(numUsesStr); err == nil {
			response.NumUses = numUses
		}
	}

	// Marshal to JSON
	jsonData, err := json.Marshal(response)
	if err != nil {
		logger.WithError(err).Error("Failed to marshal token response to JSON")
		return mcp.NewToolResultError(fmt.Sprintf("Error marshaling JSON: %v", err)), nil
	}

	logger.WithFields(log.Fields{
		"token_accessor": response.TokenAccessor,
		"policies":       response.Policies,
		"namespace":      namespace,
		"orphan":         response.Orphan,
		"renewable":      response.Renewable,
		"ttl":            response.TTL,
	}).Info("Token generated successfully")

	return mcp.NewToolResultText(string(jsonData)), nil
}
