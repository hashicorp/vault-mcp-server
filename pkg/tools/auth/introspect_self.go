// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package auth

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/vault-mcp-server/pkg/client"
	"github.com/hashicorp/vault-mcp-server/pkg/utils"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
)

// IntrospectSelf creates a tool that returns caller token details and self entity data together.
func IntrospectSelf(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("introspect_self",
			mcp.WithDescription("Introspect current Vault identity by combining auth/token/lookup-self and identity/entity/id/:entity_id (when present). Useful for policy/template-aware access analysis."),
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					IdempotentHint: utils.ToBoolPtr(true),
					ReadOnlyHint:   utils.ToBoolPtr(true),
				},
			),
			mcp.WithString("namespace",
				mcp.DefaultString(""),
				mcp.Description("Namespace path (for example 'admin/'). Defaults to current namespace.")),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return introspectSelfHandler(ctx, req, logger)
		},
	}
}

func introspectSelfHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	args, ok := req.Params.Arguments.(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("Missing or invalid arguments format"), nil
	}

	namespace, _ := args["namespace"].(string)

	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	nsClient := vault
	if namespace != "" {
		nsClient = vault.WithNamespace(namespace)
	}

	lookupSecret, err := nsClient.Logical().Read("auth/token/lookup-self")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to lookup self token: %v", err)), nil
	}
	if lookupSecret == nil || lookupSecret.Data == nil {
		return mcp.NewToolResultError("No token lookup data returned"), nil
	}

	entityID, _ := lookupSecret.Data["entity_id"].(string)
	result := map[string]interface{}{
		"namespace": namespace,
		"token":     lookupSecret.Data,
		"entity_id": entityID,
	}

	if entityID != "" {
		entityPath := fmt.Sprintf("identity/entity/id/%s", entityID)
		entitySecret, entityErr := nsClient.Logical().Read(entityPath)
		if entityErr != nil {
			result["entity_error"] = entityErr.Error()
		} else if entitySecret == nil || entitySecret.Data == nil {
			result["entity_error"] = "entity not found"
		} else {
			result["entity"] = entitySecret.Data
		}
	}

	jsonResult, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to marshal result: %v", err)), nil
	}

	return mcp.NewToolResultText(string(jsonResult)), nil
}
