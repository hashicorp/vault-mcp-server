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

// EnableAuditDevice creates a tool for enabling audit devices in Vault
func EnableAuditDevice(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("enable_audit_device",
			mcp.WithDescription("Enable an audit device in Vault"),
			mcp.WithString("path", mcp.Required(), mcp.Description("The path where the audit device will be mounted (e.g., 'file', 'syslog', 'socket')")),
			mcp.WithString("type", mcp.Required(), mcp.Description("The type of audit device (e.g., 'file', 'syslog', 'socket')")),
			mcp.WithString("description", mcp.DefaultString(""), mcp.Description("Optional description for the audit device")),
			mcp.WithObject("options", mcp.Description("Audit device specific options (e.g., file_path for file audit, facility for syslog)")),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return enableAuditDeviceHandler(ctx, req, logger)
		},
	}
}

func enableAuditDeviceHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling enable_audit_device request")

	// Extract parameters
	var path, auditType, description string
	var options map[string]interface{}

	if req.Params.Arguments != nil {
		if args, ok := req.Params.Arguments.(map[string]interface{}); ok {
			if path, ok = args["path"].(string); !ok || path == "" {
				return mcp.NewToolResultError("Missing or invalid 'path' parameter"), nil
			}

			if auditType, ok = args["type"].(string); !ok || auditType == "" {
				return mcp.NewToolResultError("Missing or invalid 'type' parameter"), nil
			}

			description, _ = args["description"].(string)

			if opts, exists := args["options"]; exists {
				if options, ok = opts.(map[string]interface{}); !ok {
					return mcp.NewToolResultError("Invalid 'options' parameter format"), nil
				}
			} else {
				options = make(map[string]interface{})
			}
		} else {
			return mcp.NewToolResultError("Invalid arguments format"), nil
		}
	} else {
		return mcp.NewToolResultError("Missing arguments"), nil
	}

	logger.WithFields(log.Fields{
		"path": path,
		"type": auditType,
	}).Debug("Enabling audit device")

	// Get Vault client from context
	client, err := GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	// Prepare audit device options - convert to map[string]string
	auditOptions := make(map[string]string)
	for key, value := range options {
		if strVal, ok := value.(string); ok {
			auditOptions[key] = strVal
		} else {
			auditOptions[key] = fmt.Sprintf("%v", value)
		}
	}

	// Prepare audit device configuration
	enableOptions := &api.EnableAuditOptions{
		Type:        auditType,
		Description: description,
		Options:     auditOptions,
	}

	// Enable the audit device
	err = client.Sys().EnableAuditWithOptions(path, enableOptions)
	if err != nil {
		logger.WithError(err).WithFields(log.Fields{
			"path": path,
			"type": auditType,
		}).Error("Failed to enable audit device")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to enable audit device at path '%s': %v", path, err)), nil
	}

	successMsg := fmt.Sprintf("Successfully enabled audit device '%s' of type '%s' at path '%s'", path, auditType, path)
	logger.WithFields(log.Fields{
		"path": path,
		"type": auditType,
	}).Info("Audit device enabled successfully")

	return mcp.NewToolResultText(successMsg), nil
}
