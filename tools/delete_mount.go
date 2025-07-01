package tools

import (
	"context"
	"fmt"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"strings"
	"vault-mcp-server/vault"
)

func DeleteMount() server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("delete-mount",
			mcp.WithDescription("Delete a secret engine mount on Vault Server at a given path."),
			mcp.WithString("path", mcp.Required(), mcp.Description("Path where the secret engine is mounted to, eg 'secrets'")),
		),
		Handler: deleteMountHandler,
	}
}

func deleteMountHandler(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	// Get the current session from context
	session := server.ClientSessionFromContext(ctx)
	if session == nil {
		return mcp.NewToolResultError("No active session"), nil
	}

	client := vault.GetVaultClient(session.SessionID())

	path := strings.TrimSuffix(strings.TrimPrefix(req.GetArguments()["path"].(string), "/"), "/") // Ensure mount is trimmed of leading/trailing slash

	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return nil, fmt.Errorf("failed to list mounts: %v", err)
	}

	if _, ok := mounts[path+"/"]; !ok {
		return nil, fmt.Errorf("mount doesn't exists")
	}

	// Delete the mount
	err = client.Sys().Unmount(path)

	if err != nil {
		return nil, fmt.Errorf("failed to delete mount: %v", err)
	}

	return mcp.NewToolResultText("mount deleted"), nil
}
