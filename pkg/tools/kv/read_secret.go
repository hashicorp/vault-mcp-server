// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package kv

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hashicorp/vault-mcp-server/pkg/client"
	"github.com/hashicorp/vault-mcp-server/pkg/utils"
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
			mcp.WithString("key",
				mcp.DefaultString(""),
				mcp.Description("A optional key in the secret to delete. If not specified, all keys in the the secret will be deleted."),
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return readSecretHandler(ctx, req, logger)
		},
	}
}

func readSecretHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling read_secret request")

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

	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	kvSecret, err := vault.KVv2(mount).Get(ctx, strings.TrimPrefix(path, "/"))
	if err != nil {
		logger.WithError(err).WithFields(log.Fields{
			"mount": mount,
			"path":  path,
		}).Error("Failed to read secret")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to read secret: %v", err)), nil
	}

	if kvSecret == nil || kvSecret.Data == nil {
		logger.WithFields(log.Fields{
			"mount": mount,
			"path":  path,
		}).Debug("Secret not found")
		return mcp.NewToolResultError(fmt.Sprintf("Secret not found at path '%s' in mount '%s'. Use 'write_secret' to write a new secret at that path.", path, mount)), nil
	}

	jsonData, err := json.Marshal(kvSecret.Data)
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
