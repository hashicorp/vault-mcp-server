// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package sys

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

// ListNamespaces creates a tool for listing Vault namespaces.
func ListNamespaces(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("list_namespaces",
			mcp.WithDescription("List child namespaces in Vault from a given namespace scope."),
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					ReadOnlyHint: utils.ToBoolPtr(true),
				},
			),
			mcp.WithString("path",
				mcp.DefaultString(""),
				mcp.Description("Optional namespace path to list under (for example: 'team-03'). Leave empty to list direct children from current scope."),
			),
			mcp.WithString("namespace",
				mcp.DefaultString(""),
				mcp.Description("Optional Vault namespace override for this call (for example: 'admin'). If not set, uses the MCP session namespace."),
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return listNamespacesHandler(ctx, req, logger)
		},
	}
}

func listNamespacesHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling list_namespaces request")

	args, ok := req.Params.Arguments.(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("Missing or invalid arguments format"), nil
	}

	path, _ := args["path"].(string)
	namespace, _ := args["namespace"].(string)

	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	ns := strings.TrimSpace(namespace)
	if ns != "" {
		vault = vault.WithNamespace(ns)
	}

	fullPath := "sys/namespaces"
	if strings.TrimSpace(path) != "" {
		fullPath = fmt.Sprintf("sys/namespaces/%s", strings.Trim(path, "/"))
	}

	secret, err := vault.Logical().List(fullPath)
	if err != nil {
		logger.WithError(err).WithFields(log.Fields{
			"namespace": namespace,
			"path":      path,
			"full_path": fullPath,
		}).Error("Failed to list namespaces")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to list namespaces: %v", err)), nil
	}

	if secret == nil || secret.Data == nil {
		return mcp.NewToolResultText("[]"), nil
	}

	keys, ok := secret.Data["keys"].([]interface{})
	if !ok {
		return mcp.NewToolResultText("[]"), nil
	}

	results := make([]string, 0, len(keys))
	for _, key := range keys {
		if keyStr, ok := key.(string); ok {
			results = append(results, keyStr)
		}
	}

	jsonData, err := json.Marshal(results)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Error marshaling JSON: %v", err)), nil
	}

	return mcp.NewToolResultText(string(jsonData)), nil
}