// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package kv

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/vault-mcp-server/pkg/client"
	"github.com/hashicorp/vault-mcp-server/pkg/utils"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
)

// WriteSecret creates a tool for writing secrets to a Vault KV mount
func WriteSecret(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("write_secret",
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					DestructiveHint: utils.ToBoolPtr(true),  // This is destructive because it overwrites existing secrets on a kv1
					IdempotentHint:  utils.ToBoolPtr(false), // We are not idempotent because writing a secret will always create a new version on the kv2
				},
			),
			mcp.WithDescription("Writes a secret to a KV store in Vault using the specified path and mount. The data parameter is a complete key-value map that will replace the secret at the given path. Supports both KV v1 and v2 mounts. If a KV v2 mount is detected, the currently stored version of the secret will be returned."),
			mcp.WithString("mount",
				mcp.Required(),
				mcp.Description("The mount path of the secret engine. For example, if you want to write to 'secrets/application/credentials', this should be 'secrets' without the trailing slash."),
			),
			mcp.WithString("path",
				mcp.Required(),
				mcp.Description("The full path to write the secret to without the mount prefix. For example, if you want to write to 'secrets/application/credentials', this should be 'application/credentials'."),
			),
			mcp.WithObject("data",
				mcp.Required(),
				mcp.Description("A complete key-value map of the secret data to write. For example: {\"username\": \"admin\", \"password\": \"s3cret\"}. This will replace the entire secret at the given path."),
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return writeSecretHandler(ctx, req, logger)
		},
	}
}

func writeSecretHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling write_secret request")

	// Extract parameters
	args, ok := req.Params.Arguments.(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("Missing or invalid arguments format"), nil
	}

	mount, err := utils.ExtractMountPath(args)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	path, ok := args["path"].(string)
	if !ok || path == "" {
		return mcp.NewToolResultError("Missing or invalid 'path' parameter"), nil
	}

	data, ok := args["data"].(map[string]interface{})
	if !ok || data == nil {
		return mcp.NewToolResultError("Missing or invalid 'data' parameter — must be a JSON object"), nil
	}

	logger.WithFields(log.Fields{
		"mount": mount,
		"path":  path,
	}).Debug("Writing secret")

	// Get Vault client from context
	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	isV2, err := getMountInfo(vault, mount)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	// Construct the full path
	fullPath := fmt.Sprintf("%s/%s", mount, strings.TrimPrefix(path, "/"))
	if isV2 {
		fullPath = fmt.Sprintf("%s/data/%s", mount, strings.TrimPrefix(path, "/"))
	}

	// Prepare the write data
	var writeData map[string]interface{}
	if isV2 {
		writeData = map[string]interface{}{
			"data": data,
		}
	} else {
		writeData = data
	}

	// Write the secret
	versionInfo, err := vault.Logical().Write(fullPath, writeData)
	if err != nil {
		logger.WithError(err).WithFields(log.Fields{
			"mount":     mount,
			"path":      path,
			"full_path": fullPath,
		}).Error("Failed to write secret")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to write secret: %v", err)), nil
	}

	successMsg := fmt.Sprintf("Successfully wrote secret to path '%s' in mount '%s'", path, mount)

	// Write out the version information if available
	if versionInfo != nil && versionInfo.Data != nil {
		successMsg = fmt.Sprintf("Successfully wrote version %v of the secret to path '%s' in mount '%s'", versionInfo.Data["version"], path, mount)
	}

	logger.WithFields(log.Fields{
		"mount": mount,
		"path":  path,
		"v2":    isV2,
	}).Info("Successfully wrote secret")

	return mcp.NewToolResultText(successMsg), nil
}
