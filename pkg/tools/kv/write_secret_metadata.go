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

// WriteSecretMetadata creates a tool for writing custom metadata on a KV v2 secret path.
func WriteSecretMetadata(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("write_secret_metadata",
			mcp.WithDescription("Write or update custom metadata (owner, email, app, or any key-value pairs) for a secret in a KV v2 mount. Only updates the metadata fields provided; does not affect the secret data or versions."),
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					DestructiveHint: utils.ToBoolPtr(false),
					IdempotentHint:  utils.ToBoolPtr(true),
				},
			),
			mcp.WithString("mount",
				mcp.Required(),
				mcp.Description("The mount path of the KV v2 secret engine (e.g. 'secrets')."),
			),
			mcp.WithString("path",
				mcp.Required(),
				mcp.Description("The path to the secret without the mount prefix (e.g. 'admin-demo-secret')."),
			),
			mcp.WithString("custom_metadata",
				mcp.Required(),
				mcp.Description("JSON object with custom metadata key-value pairs to set (e.g. '{\"owner\":\"team-admin\",\"email\":\"admin@example.com\",\"app\":\"my-app\"}')."),
			),
			mcp.WithString("namespace",
				mcp.DefaultString(""),
				mcp.Description("Optional Vault namespace override for this call (for example: 'admin/team-03'). If not set, uses the MCP session namespace."),
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return writeSecretMetadataHandler(ctx, req, logger)
		},
	}
}

func writeSecretMetadataHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling write_secret_metadata request")

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

	customMetadataRaw, ok := args["custom_metadata"].(string)
	if !ok || strings.TrimSpace(customMetadataRaw) == "" {
		return mcp.NewToolResultError("Missing or invalid 'custom_metadata' parameter (must be a JSON object string)"), nil
	}

	customMetadata := map[string]interface{}{}
	if err := json.Unmarshal([]byte(customMetadataRaw), &customMetadata); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("'custom_metadata' is not valid JSON: %v", err)), nil
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
		return mcp.NewToolResultError(fmt.Sprintf("mount '%s' not found", mount)), nil
	}
	if m.Type != "kv" {
		return mcp.NewToolResultError(fmt.Sprintf("mount '%s' is not a KV engine (type: %s)", mount, m.Type)), nil
	}
	if m.Options == nil || m.Options["version"] != "2" {
		return mcp.NewToolResultError(fmt.Sprintf("mount '%s' is KV v1; custom metadata is only supported on KV v2", mount)), nil
	}

	metadataPath := strings.TrimSuffix(mount, "/") + "/metadata/" + strings.TrimPrefix(path, "/")

	payload := map[string]interface{}{
		"custom_metadata": customMetadata,
	}

	_, err = vault.Logical().Write(metadataPath, payload)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to write metadata: %v", err)), nil
	}

	result := map[string]interface{}{
		"message":         fmt.Sprintf("Custom metadata written successfully for path '%s' in mount '%s'", path, mount),
		"path":            path,
		"mount":           mount,
		"custom_metadata": customMetadata,
	}
	if namespace != "" {
		result["namespace"] = namespace
	}

	out, _ := json.MarshalIndent(result, "", "  ")
	return mcp.NewToolResultText(string(out)), nil
}