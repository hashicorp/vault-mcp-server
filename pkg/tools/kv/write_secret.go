// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package kv

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault-mcp-server/pkg/client"
	"github.com/hashicorp/vault-mcp-server/pkg/utils"

	"strings"

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
			mcp.WithDescription("Writes a secret value to a KV store in Vault using the specified path and mount. Supports both KV v1 and v2 mounts. If a KV v2 mount is detected, the currently stored version of the secret will be returned."),
			mcp.WithString("mount",
				mcp.Required(),
				mcp.Description("The mount path of the secret engine. For example, if you want to write to 'secrets/application/credentials', this should be 'secrets' without the trailing slash."),
			),
			mcp.WithString("path",
				mcp.Required(),
				mcp.Description("The full path to write the secret to without the mount prefix. For example, if you want to write to 'secrets/application/credentials', this should be 'application/credentials'."),
			),
			mcp.WithString("key",
				mcp.Required(),
				mcp.Description("The key name for the secret. For example if you want to write mysecret=myvalue, this should be 'mysecret'"),
			),
			mcp.WithString("value",
				mcp.Required(),
				mcp.Description("The value to store the given key. For example if you want to write mysecret=myvalue, this should be 'myvalue'"),
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

	key, ok := args["key"].(string)
	if !ok || key == "" {
		return mcp.NewToolResultError("Missing or invalid 'key' parameter"), nil
	}

	value, ok := args["value"].(string)
	if !ok || value == "" {
		return mcp.NewToolResultError("Missing or invalid 'value' parameter"), nil
	}

	logger.WithFields(log.Fields{
		"mount": mount,
		"path":  path,
		"key":   key,
	}).Debug("Writing secret")

	// Get Vault client from context
	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	mounts, err := vault.Sys().ListMounts()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to list mounts: %v", err)), nil
	}

	// Default to a v1 KV path
	fullPath := fmt.Sprintf("%s/%s", mount, strings.TrimPrefix(path, "/"))

	isV2 := false

	// Check if the mount exists
	if m, ok := mounts[mount+"/"]; ok {
		// is it a KV v2 mount?
		if m.Options["version"] == "2" {
			isV2 = true
			// Construct the full path for reading (KV v2 format)
			fullPath = fmt.Sprintf("%s/data/%s", mount, strings.TrimPrefix(path, "/"))
		}
	} else {
		return mcp.NewToolResultError(fmt.Sprintf("mount path '%s' does not exist. Use 'create_mount' with the type kv2 to create the mount.", mount)), nil
	}

	// Read the current secret so we can update it with the new key-value pair (or replace it)
	currentSecret, err := vault.Logical().Read(fullPath)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to read secret: %v", err)), nil
	}

	var secretData map[string]interface{}

	if currentSecret != nil {
		secretData = currentSecret.Data
	}

	if isV2 {
		if secretData == nil {
			secretData = map[string]interface{}{
				"data": make(map[string]interface{}),
			}
		}
		secretData["data"].(map[string]interface{})[key] = value
	} else {
		if secretData == nil {
			secretData = map[string]interface{}{}
		}
		secretData[key] = value
	}

	// Write (or update) the secret
	versionInfo, err := vault.Logical().Write(fullPath, secretData)
	if err != nil {
		logger.WithError(err).WithFields(log.Fields{
			"mount":     mount,
			"path":      path,
			"key":       key,
			"full_path": fullPath,
		}).Error("Failed to write secret")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to write secret: %v", err)), nil
	}

	successMsg := fmt.Sprintf("Successfully updated the secret, adding or updating the key '%s' on path '%s' in mount '%s'", key, path, mount)

	// Write out the version information if available as the AI may decide on a different approach if a version is provided
	if versionInfo != nil && versionInfo.Data != nil {
		successMsg = fmt.Sprintf("Successfully wrote version %v of the secret to path '%s' in mount '%s' with key '%s'", versionInfo.Data["version"], path, mount, key)
	}

	logger.WithFields(log.Fields{
		"mount": mount,
		"path":  path,
		"key":   key,
		"v2":    isV2,
	}).Info("Successfully wrote secret")

	return mcp.NewToolResultText(successMsg), nil
}
