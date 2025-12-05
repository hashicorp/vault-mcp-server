// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package kv

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/hashicorp/vault-mcp-server/pkg/client"
	"github.com/hashicorp/vault-mcp-server/pkg/utils"

	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
)

// ReadSecret creates a tool for reading secrets from a Vault KV mount
func ReadSecret(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("read_secret",
			mcp.WithDescription("Read a secret from a KV mount in at a specific path in Vault."),
			mcp.WithString("mount",
				mcp.Required(),
				mcp.Description("The mount path of the secret engine. For example, if you want to read from 'secrets/application/credentials', this should be 'secrets' without the trailing slash."),
			),
			mcp.WithString("path",
				mcp.Required(),
				mcp.Description("The full path to read the secret to without the mount prefix. For example, if you want to read from 'secrets/application/credentials', this should be 'application/credentials'."),
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return readSecretHandler(ctx, req, logger)
		},
	}
}

func readSecretHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling read_secret request")

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

	logger.WithFields(log.Fields{
		"mount": mount,
		"path":  path,
	}).Debug("Reading secret")

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

	// Read the secret
	secret, err := vault.Logical().Read(fullPath)
	if err != nil {
		logger.WithError(err).WithFields(log.Fields{
			"mount":     mount,
			"path":      path,
			"full_path": fullPath,
		}).Error("Failed to read secret")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to read secret: %v", err)), nil
	}

	if secret == nil {
		logger.WithFields(log.Fields{
			"mount": mount,
			"path":  path,
		}).Debug("Secret not found")
		return mcp.NewToolResultError(fmt.Sprintf("Secret not found at path '%s' in mount '%s'. Use 'write_secret' to write a new secret at that path.", path, mount)), nil
	}

	// Handle the data structure differently for v1 and v2
	var secretData interface{}

	if isV2 {
		if secret.Data["data"] == nil {
			metaData, ok := secret.Data["metadata"].(map[string]interface{})
			if !ok {
				return mcp.NewToolResultError("unexpected secret metadata format for v2 API"), nil
			}
			if metaData["deletion_time"] != nil {
				return mcp.NewToolResultError(fmt.Sprintf("Secret at path '%s' in mount '%s' is deleted and cannot be read.", path, mount)), nil
			}
		}
		// V2 API structure: secret.Data["data"] contains the actual key-value pairs
		data, ok := secret.Data["data"].(map[string]interface{})
		if !ok {
			return mcp.NewToolResultError("unexpected secret data format for v2 API"), nil
		}
		secretData = data
	} else {
		// V1 API structure: secret.Data directly contains the key-value pairs
		secretData = secret.Data
	}

	// Marshal to JSON
	jsonData, err := json.Marshal(secretData)
	if err != nil {
		logger.WithError(err).Error("Failed to marshal secret to JSON")
		return mcp.NewToolResultError(fmt.Sprintf("Error marshaling JSON: %v", err)), nil
	}

	logger.WithFields(log.Fields{
		"mount": mount,
		"path":  path,
	}).Debug("Successfully read secret")

	return mcp.NewToolResultText(string(jsonData)), nil
}
