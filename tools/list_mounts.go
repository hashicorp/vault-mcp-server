package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"vault-mcp-server/vault"
)

func ListMounts() server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("list-mounts",
			mcp.WithDescription("List the available mounted secrets engines on a Vault Server"),
		),
		Handler: listMountHandler,
	}
}

func listMountHandler(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	// Get the current session from context
	session := server.ClientSessionFromContext(ctx)
	if session == nil {
		return mcp.NewToolResultError("No active session"), nil
	}

	client := vault.GetVaultClient(session.SessionID())

	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return nil, fmt.Errorf("failed to list mounts: %v", err)
	}

	// Marshal the struct to JSON (returns a []byte slice)
	jsonData, err := json.Marshal(mounts)
	if err != nil {
		return nil, fmt.Errorf("error marshaling JSON: %v", err)
	}

	// Convert the []byte slice to a string
	jsonString := string(jsonData)

	return mcp.NewToolResultText(jsonString), nil
}
