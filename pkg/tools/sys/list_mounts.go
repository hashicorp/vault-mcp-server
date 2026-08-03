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

type Mount struct {
	Name            string `json:"name"`              // Name of the mount
	Type            string `json:"type"`              // Type of the mount (e.g., kv, kv2)
	Description     string `json:"description"`       // Description of the mount, if any
	DefaultLeaseTTL int    `json:"default_lease_ttl"` // Default lease TTL for the mount, if any
	MaxLeaseTTL     int    `json:"max_lease_ttl"`     // Max lease TTL for the mount, if any
}

// ListMounts creates a tool for listing Vault mounts
func ListMounts(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("list_mounts",
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					IdempotentHint: utils.ToBoolPtr(true),
				},
			),
			mcp.WithDescription("List the available mounted secrets engines on a Vault Server."),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return listMountHandler(ctx, req, logger)
		},
	}
}

func listMountHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling list_mounts request")

	// Get Vault client from context
	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	// List mounts from Vault. Some Vault policies forbid sys/mounts; if so, fall back
	// to sys/internal/ui/mounts (used by the Vault UI) when available.
	mounts, err := vault.Sys().ListMounts()
	if err != nil {
		logger.WithError(err).Warn("sys/mounts failed; attempting sys/internal/ui/mounts")

		secret, readErr := vault.Logical().Read("sys/internal/ui/mounts")
		if readErr != nil {
			logger.WithError(readErr).Error("Failed to list mounts via sys/internal/ui/mounts")
			return mcp.NewToolResultError(fmt.Sprintf("Failed to list mounts: %v", err)), nil
		}
		if secret == nil || secret.Data == nil {
			return mcp.NewToolResultError(fmt.Sprintf("Failed to list mounts: %v", err)), nil
		}

		data := secret.Data
		// Some Vault versions nest mount data under known keys.
		if nested, ok := data["mounts"].(map[string]interface{}); ok {
			data = nested
		} else if nested, ok := data["data"].(map[string]interface{}); ok {
			data = nested
		}
		// Vault UI responses may group mounts by category (e.g. "secret", "auth").
		if nested, ok := data["secret"].(map[string]interface{}); ok {
			data = nested
		}

		var results []*Mount
		for k, raw := range data {
			m, ok := raw.(map[string]interface{})
			if !ok {
				continue
			}

			mt := &Mount{Name: k}
			if typ, ok := m["type"].(string); ok {
				mt.Type = typ
			}
			if desc, ok := m["description"].(string); ok {
				mt.Description = desc
			}
			if cfg, ok := m["config"].(map[string]interface{}); ok {
				if v, ok := cfg["default_lease_ttl"].(float64); ok {
					mt.DefaultLeaseTTL = int(v)
				}
				if v, ok := cfg["max_lease_ttl"].(float64); ok {
					mt.MaxLeaseTTL = int(v)
				}
			}

			results = append(results, mt)
		}

		// Marshal the struct to JSON
		jsonData, err := json.Marshal(results)
		if err != nil {
			logger.WithError(err).Error("Failed to marshal mounts to JSON")
			return mcp.NewToolResultError(fmt.Sprintf("Error marshaling JSON: %v", err)), nil
		}

		logger.WithField("mount_count", len(results)).Debug("Successfully listed mounts")
		return mcp.NewToolResultText(string(jsonData)), nil
	}

	var results []*Mount
	for k, v := range mounts {
		mount := &Mount{
			Name:            k,
			Type:            v.Type,
			Description:     v.Description,
			DefaultLeaseTTL: v.Config.DefaultLeaseTTL,
			MaxLeaseTTL:     v.Config.MaxLeaseTTL,
		}
		results = append(results, mount)
	}

	// Marshal the struct to JSON
	jsonData, err := json.Marshal(results)
	if err != nil {
		logger.WithError(err).Error("Failed to marshal mounts to JSON")
		return mcp.NewToolResultError(fmt.Sprintf("Error marshaling JSON: %v", err)), nil
	}

	logger.WithField("mount_count", len(results)).Debug("Successfully listed mounts")
	return mcp.NewToolResultText(string(jsonData)), nil
}
