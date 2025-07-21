// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
)

// DisableAuditDevice creates a tool for disabling audit devices in Vault
func DisableAuditDevice(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("disable_audit_device",
			mcp.WithDescription("Disable an audit device in Vault"),
			mcp.WithString("path", mcp.Required(), mcp.Description("The path of the audit device to disable (e.g., 'file', 'syslog')")),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return disableAuditDeviceHandler(ctx, req, logger)
		},
	}
}

func disableAuditDeviceHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling disable_audit_device request")

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

	logger.WithField("path", path).Debug("Disabling audit device")

	// Get Vault client from context
	client, err := GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	// Check if audit device exists before trying to disable
	audits, err := client.Sys().ListAudit()
	if err != nil {
		logger.WithError(err).Error("Failed to list audit devices")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to list audit devices: %v", err)), nil
	}

	found := false
	for auditPath := range audits {
		if auditPath == path+"/" || auditPath == path {
			found = true
			break
		}
	}

	if !found {
		return mcp.NewToolResultError(fmt.Sprintf("Audit device at path '%s' does not exist", path)), nil
	}

	// Disable the audit device
	err = client.Sys().DisableAudit(path)
	if err != nil {
		logger.WithError(err).WithField("path", path).Error("Failed to disable audit device")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to disable audit device at path '%s': %v", path, err)), nil
	}

	successMsg := fmt.Sprintf("Successfully disabled audit device at path '%s'", path)
	logger.WithField("path", path).Info("Audit device disabled successfully")

	return mcp.NewToolResultText(successMsg), nil
}
