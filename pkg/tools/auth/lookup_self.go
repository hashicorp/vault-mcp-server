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

// LookupSelf creates a tool for reading details about the caller token.
func LookupSelf(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("lookup_self",
			mcp.WithDescription("Look up details about the current Vault token (auth/token/lookup-self), including policies, entity_id, display_name, TTL, and metadata."),
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
			return lookupSelfHandler(ctx, req, logger)
		},
	}
}

func lookupSelfHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
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

	secret, err := nsClient.Logical().Read("auth/token/lookup-self")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to lookup self token: %v", err)), nil
	}
	if secret == nil || secret.Data == nil {
		return mcp.NewToolResultError("No token lookup data returned"), nil
	}

	result := map[string]interface{}{
		"namespace": namespace,
		"data":      secret.Data,
	}

	jsonResult, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to marshal result: %v", err)), nil
	}

	return mcp.NewToolResultText(string(jsonResult)), nil
}
