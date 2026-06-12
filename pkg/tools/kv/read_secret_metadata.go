// Copyright IBM Corp. 2025, 2026
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

// ReadSecretMetadata creates a tool for reading KV v2 metadata for a secret path.
func ReadSecretMetadata(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("read_secret_metadata",
			mcp.WithDescription("Read metadata for a secret from a KV v2 mount at a specific path in Vault."),
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					ReadOnlyHint: utils.ToBoolPtr(true),
				},
			),
			mcp.WithString("mount",
				mcp.Required(),
				mcp.Description("The mount path of the secret engine. For example, if you want to read from 'secrets/application/credentials', this should be 'secrets' without the trailing slash."),
			),
			mcp.WithString("path",
				mcp.Required(),
				mcp.Description("The full path to read metadata for without the mount prefix. For example, if you want to read from 'secrets/application/credentials', this should be 'application/credentials'."),
			),
			mcp.WithString("namespace",
				mcp.DefaultString(""),
				mcp.Description("Optional Vault namespace override for this call (for example: 'admin/team-03'). If not set, uses the MCP session namespace."),
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return readSecretMetadataHandler(ctx, req, logger)
		},
	}
}

func readSecretMetadataHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling read_secret_metadata request")

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
	namespace, _ := args["namespace"].(string)

	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}
	vault = withOptionalNamespace(vault, namespace)

	mounts, err := vault.Sys().ListMounts()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to list mounts: %v", err)), nil
	}

	m, exists := mounts[mount+"/"]
	if !exists {
		return mcp.NewToolResultError(fmt.Sprintf("mount path '%s' does not exist. Use 'create_mount' with the type kv2 to create the mount.", mount)), nil
	}
	if m.Type != "kv" || m.Options["version"] != "2" {
		return mcp.NewToolResultError(fmt.Sprintf("mount path '%s' is not KV v2. Metadata is only available on KV v2 mounts.", mount)), nil
	}

	fullPath := fmt.Sprintf("%s/metadata/%s", mount, strings.TrimPrefix(path, "/"))
	secret, err := vault.Logical().Read(fullPath)
	if err != nil {
		logger.WithError(err).WithFields(log.Fields{
			"mount":     mount,
			"path":      path,
			"full_path": fullPath,
		}).Error("Failed to read secret metadata")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to read secret metadata: %v", err)), nil
	}

	if secret == nil || secret.Data == nil {
		return mcp.NewToolResultError(fmt.Sprintf("Secret metadata not found at path '%s' in mount '%s'.", path, mount)), nil
	}

	jsonData, err := json.Marshal(secret.Data)
	if err != nil {
		logger.WithError(err).Error("Failed to marshal secret metadata to JSON")
		return mcp.NewToolResultError(fmt.Sprintf("Error marshaling JSON: %v", err)), nil
	}

	return mcp.NewToolResultText(string(jsonData)), nil
}