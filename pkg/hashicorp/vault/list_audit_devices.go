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

// ListAuditDevices creates a tool for listing all enabled audit devices in Vault
func ListAuditDevices(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("list_audit_devices",
			mcp.WithDescription("List all enabled audit devices in Vault"),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return listAuditDevicesHandler(ctx, req, logger)
		},
	}
}

func listAuditDevicesHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling list_audit_devices request")

	// Get Vault client from context
	client, err := GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	// List audit devices from Vault
	audits, err := client.Sys().ListAudit()
	if err != nil {
		logger.WithError(err).Error("Failed to list audit devices")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to list audit devices: %v", err)), nil
	}

	var devices []*AuditDevice
	for path, audit := range audits {
		devices = append(devices, &AuditDevice{
			Type:        audit.Type,
			Description: audit.Description,
			Options:     audit.Options,
			Path:        path,
		})
	}

	// Marshal to JSON
	jsonData, err := json.Marshal(devices)
	if err != nil {
		logger.WithError(err).Error("Failed to marshal audit devices to JSON")
		return mcp.NewToolResultError(fmt.Sprintf("Error marshaling JSON: %v", err)), nil
	}

	logger.WithField("audit_device_count", len(devices)).Debug("Successfully listed audit devices")
	return mcp.NewToolResultText(string(jsonData)), nil
}
