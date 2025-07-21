// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
)

// AuthMethod represents an authentication method in Vault
type AuthMethod struct {
	Name                  string                   `json:"name"`
	Type                  string                   `json:"type"`
	Description           string                   `json:"description"`
	Accessor              string                   `json:"accessor"`
	Local                 bool                     `json:"local"`
	SealWrap              bool                     `json:"seal_wrap"`
	ExternalEntropyAccess bool                     `json:"external_entropy_access"`
	Config                *AuthMethodConfig        `json:"config"`
	Options               map[string]string        `json:"options"`
	UUID                  string                   `json:"uuid"`
	PluginVersion         string                   `json:"plugin_version"`
	RunningSha256         string                   `json:"running_sha256"`
	DeprecationStatus     string                   `json:"deprecation_status"`
	RootRotationConfig    *RootCredentialsRotation `json:"root_rotation_config,omitempty"`
}

// AuthMethodConfig represents the configuration of an auth method
type AuthMethodConfig struct {
	DefaultLeaseTTL int    `json:"default_lease_ttl"`
	MaxLeaseTTL     int    `json:"max_lease_ttl"`
	ForceNoCache    bool   `json:"force_no_cache"`
	TokenType       string `json:"token_type"`
}

// RootCredentialsRotation represents root credentials rotation configuration and status
type RootCredentialsRotation struct {
	Supported              bool   `json:"supported"`                    // Whether the auth method supports root credential rotation
	Enabled                bool   `json:"enabled"`                      // Whether auto-rotation is enabled
	RotationPeriod         int    `json:"rotation_period,omitempty"`    // Auto-rotation period in seconds (0 = disabled)
	LastRotationTime       string `json:"last_rotation_time,omitempty"` // ISO timestamp of last rotation
	NextRotationTime       string `json:"next_rotation_time,omitempty"` // ISO timestamp of next scheduled rotation
	RotationStatus         string `json:"rotation_status,omitempty"`    // Current rotation status
	ManualRotationRequired bool   `json:"manual_rotation_required"`     // Whether manual rotation is needed
	DaysSinceLastRotation  int    `json:"days_since_last_rotation"`     // Days since last rotation (-1 if never)
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

		// Collect root credentials rotation information
		authMethod.RootRotationConfig = collectRootRotationConfig(ctx, client, k, v.Type, logger)

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

// collectRootRotationConfig collects root credentials rotation information for an auth method
func collectRootRotationConfig(ctx context.Context, client *api.Client, authPath, authType string, logger *log.Logger) *RootCredentialsRotation {
	// Initialize with defaults
	rotation := &RootCredentialsRotation{
		Supported:              false,
		Enabled:                false,
		ManualRotationRequired: false,
		DaysSinceLastRotation:  -1,
	}

	// Check if this auth method type supports root credential rotation
	supportedTypes := map[string]bool{
		"aws":        true,
		"azure":      true,
		"gcp":        true,
		"ldap":       true,
		"database":   true,
		"ad":         true,
		"kubernetes": false, // K8s doesn't typically have rotatable root creds
		"github":     false, // GitHub tokens are managed externally
		"userpass":   false, // No root credentials to rotate
		"token":      false, // Token auth doesn't have root credentials
	}

	if supported, exists := supportedTypes[authType]; exists && supported {
		rotation.Supported = true
	} else {
		// For unknown types, assume they might support it
		rotation.Supported = true
	}

	if !rotation.Supported {
		return rotation
	}

	// Try to get root credentials configuration
	cleanPath := strings.TrimSuffix(authPath, "/")
	configPath := fmt.Sprintf("auth/%s/config/rotate-root", cleanPath)

	logger.WithFields(log.Fields{
		"auth_path":   cleanPath,
		"auth_type":   authType,
		"config_path": configPath,
	}).Debug("Checking root rotation configuration")

	// Attempt to read the rotate-root configuration
	secret, err := client.Logical().Read(configPath)
	if err != nil {
		logger.WithError(err).WithField("path", configPath).Debug("Failed to read root rotation config (may not be configured)")
		return rotation
	}

	if secret == nil || secret.Data == nil {
		logger.WithField("path", configPath).Debug("No root rotation configuration found")
		return rotation
	}

	// Parse rotation configuration
	if val, exists := secret.Data["auto_rotate"]; exists {
		if enabled, ok := val.(bool); ok {
			rotation.Enabled = enabled
		}
	}

	if val, exists := secret.Data["rotate_period"]; exists {
		if period, ok := val.(int); ok {
			rotation.RotationPeriod = period
		} else if periodStr, ok := val.(string); ok {
			// Handle duration strings like "24h", "30d", etc.
			if duration, err := time.ParseDuration(periodStr); err == nil {
				rotation.RotationPeriod = int(duration.Seconds())
			}
		}
	}

	// Try to get last rotation information
	statusPath := fmt.Sprintf("auth/%s/config/rotate-root/status", cleanPath)
	statusSecret, err := client.Logical().Read(statusPath)
	if err == nil && statusSecret != nil && statusSecret.Data != nil {
		if val, exists := statusSecret.Data["last_rotation_time"]; exists {
			if lastRotation, ok := val.(string); ok {
				rotation.LastRotationTime = lastRotation

				// Calculate days since last rotation
				if lastTime, err := time.Parse(time.RFC3339, lastRotation); err == nil {
					daysSince := int(time.Since(lastTime).Hours() / 24)
					rotation.DaysSinceLastRotation = daysSince
				}
			}
		}

		if val, exists := statusSecret.Data["status"]; exists {
			if status, ok := val.(string); ok {
				rotation.RotationStatus = status
			}
		}
	}

	// Calculate next rotation time if auto-rotation is enabled
	if rotation.Enabled && rotation.RotationPeriod > 0 && rotation.LastRotationTime != "" {
		if lastTime, err := time.Parse(time.RFC3339, rotation.LastRotationTime); err == nil {
			nextTime := lastTime.Add(time.Duration(rotation.RotationPeriod) * time.Second)
			rotation.NextRotationTime = nextTime.Format(time.RFC3339)
		}
	}

	// Determine if manual rotation is required (arbitrary threshold of 90 days)
	if rotation.DaysSinceLastRotation > 90 {
		rotation.ManualRotationRequired = true
	}

	return rotation
}
