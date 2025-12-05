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

// DeleteSecret creates a tool for deleting secrets from a Vault KV mount
func DeleteSecret(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("delete_secret",
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					DestructiveHint: utils.ToBoolPtr(true),
					IdempotentHint:  utils.ToBoolPtr(false),
				},
			),
			mcp.WithDescription("Delete a secret from a KV mount in Vault using the specified path and mount. If you specify a key, only that key will be deleted. If no key is specified or you delete the last key, the entire secret will be deleted."),
			mcp.WithString("mount",
				mcp.Required(),
				mcp.Description("The mount path of the secret engine. For example, if you want to delete to 'secrets/application/credentials', this should be 'secrets' without the trailing slash."),
			),
			mcp.WithString("path",
				mcp.Required(),
				mcp.Description("The full path to delete the secret to without the mount prefix. For example, if you want to delete to 'secrets/application/credentials', this should be 'application/credentials'."),
			),
			mcp.WithString("key",
				mcp.DefaultString(""),
				mcp.Description("A optional key in the secret to delete. If not specified, all keys in the the secret will be deleted."),
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return deleteSecretHandler(ctx, req, logger)
		},
	}
}

func deleteSecretHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling delete_secret request")

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

	// Can be empty to delete the entire secret
	key, ok := args["key"].(string)
	if !ok {
		return mcp.NewToolResultError("Missing or invalid 'key' parameter"), nil
	}

	logger.WithFields(log.Fields{
		"mount": mount,
		"path":  path,
		"key":   key,
	}).Debug("Deleting secret")

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

	if currentSecret == nil {
		return mcp.NewToolResultError(fmt.Sprintf("no secret exists at path '%s' in mount '%s'", path, mount)), nil
	}

	if isV2 {
		// V2 Secrets can be marked deleted, we need to check the metadata deletion_time
		if currentSecret.Data["data"] == nil {
			metaData, ok := currentSecret.Data["metadata"].(map[string]interface{})
			if !ok {
				return mcp.NewToolResultError("unexpected secret metadata format for v2 API"), nil
			}
			if metaData["deletion_time"] != nil {
				return mcp.NewToolResultError(fmt.Sprintf("secret at path '%s' in mount '%s' is deleted and cannot be read.", path, mount)), nil
			}
			return mcp.NewToolResultError(fmt.Sprintf("no secret exists at path '%s' in mount '%s'", path, mount)), nil
		}
	}

	if key != "" {

		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to read secret: %v", err)), nil
		}

		var secretData map[string]interface{}
		var secretsMap map[string]interface{}

		if isV2 {
			// V2 API structure: secret.Data["data"] contains the actual key-value pairs
			data, ok := currentSecret.Data["data"].(map[string]interface{})
			if !ok {
				return mcp.NewToolResultError("unexpected secret data format for v2 API"), nil
			}
			secretData = data
			secretsMap = secretData["data"].(map[string]interface{})
		} else {
			// V1 API structure: secret.Data directly contains the key-value pairs
			secretData = currentSecret.Data
			secretsMap = secretData
		}

		// Delete the specified key from the secret
		delete(secretsMap, key)

		// If we have no keys left, we should not write an empty secret
		if len(secretsMap) != 0 {
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

			successMsg := fmt.Sprintf("Successfully updated the secret, removing the key '%s' on path '%s' in mount '%s'", key, path, mount)

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

	}

	// Delete the secret
	_, err = vault.Logical().Delete(fullPath)
	if err != nil {
		logger.WithError(err).WithFields(log.Fields{
			"mount":     mount,
			"path":      path,
			"key":       key,
			"full_path": fullPath,
		}).Error("Failed to delete secret")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to delete secret: %v", err)), nil
	}

	successMsg := fmt.Sprintf("Successfully deleted secret at path '%s' in mount '%s'", path, mount)

	logger.WithFields(log.Fields{
		"mount": mount,
		"path":  path,
		"key":   key,
		"v2":    isV2,
	}).Info("Successfully deleted secret")

	return mcp.NewToolResultText(successMsg), nil
}
