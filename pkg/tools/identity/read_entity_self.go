// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package identity

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

// ReadEntitySelf creates a tool for reading the caller's identity entity.
func ReadEntitySelf(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("read_entity_self",
			mcp.WithDescription("Read the Vault identity entity associated with the current token by resolving entity_id from auth/token/lookup-self. Includes entity metadata and aliases."),
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
			return readEntitySelfHandler(ctx, req, logger)
		},
	}
}

func readEntitySelfHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
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
	if entityID == "" {
		return mcp.NewToolResultError("Current token has no entity_id"), nil
	}

	entityPath := fmt.Sprintf("identity/entity/id/%s", entityID)
	entitySecret, err := nsClient.Logical().Read(entityPath)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to read entity for self token: %v", err)), nil
	}
	if entitySecret == nil || entitySecret.Data == nil {
		return mcp.NewToolResultError("Self entity not found"), nil
	}

	result := map[string]interface{}{
		"namespace": namespace,
		"entity_id": entityID,
		"entity":    entitySecret.Data,
	}

	jsonResult, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to marshal result: %v", err)), nil
	}

	return mcp.NewToolResultText(string(jsonResult)), nil
}
