package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"vault-mcp-server/vault"
)

func ListSecrets() server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("list-secrets",
			mcp.WithDescription("List the available secrets on a Vault Server at a given path"),
			mcp.WithString("mount", mcp.Required(), mcp.Description("The mount path (e.g., 'secrets' or 'kv')")),
			mcp.WithString("path", mcp.Required(),
				mcp.Description("The full path to write the secret to, excluding the mount (e.g., 'foo/bar')"),
				mcp.DefaultString(""),
			),
		),
		Handler: listSecretsHandler,
	}
}

func listSecretsHandler(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	// Get the current session from context
	session := server.ClientSessionFromContext(ctx)
	if session == nil {
		return mcp.NewToolResultError("No active session"), nil
	}

	client := vault.GetVaultClient(session.SessionID())

	mount := req.GetArguments()["mount"].(string)
	path := req.GetArguments()["path"].(string)

	path = mount + "/" + path

	value, err := client.Logical().List(path)
	if err != nil {
		return nil, err
	}

	if value == nil {
		return mcp.NewToolResultText("path does not contain any values"), nil
	}

	// Marshal the struct to JSON (returns a []byte slice)
	jsonData, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("error marshaling JSON: %v", err)
	}

	// Convert the []byte slice to a string
	jsonString := string(jsonData)

	return mcp.NewToolResultText(jsonString), nil
}
