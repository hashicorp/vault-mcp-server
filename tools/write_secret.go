package tools

import (
    "context"
    "encoding/json"
    "fmt"
    "github.com/mark3labs/mcp-go/mcp"
    "github.com/mark3labs/mcp-go/server"
    "vault-mcp-server/vault"
)

func WriteSecret() server.ServerTool {
    return server.ServerTool{
        Tool: mcp.NewTool("write-secret",
            mcp.WithDescription("Write a secret on a Vault Server"),
            mcp.WithString("mount", mcp.Required(), mcp.Description("The mount path (e.g., 'secrets' or 'kv')")),
            mcp.WithString("path", mcp.Required(), mcp.Description("The full path to write the secret to, excluding the mount (e.g., 'foo/bar')")),
            mcp.WithString("key", mcp.Required(), mcp.Description("The key name for the secret")),
            mcp.WithString("value", mcp.Required(), mcp.Description("The value to store")),
        ),
        Handler: writeSecretHandler,
    }
}

func writeSecretHandler(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
    // Get the current session from context
    session := server.ClientSessionFromContext(ctx)
    if session == nil {
        return mcp.NewToolResultError("No active session"), nil
    }

    client := vault.GetVaultClient(session.SessionID())

    mount := req.GetArguments()["mount"].(string)
    path := req.GetArguments()["path"].(string)
    key := req.GetArguments()["key"].(string)
    value := req.GetArguments()["value"].(string)

    mounts, err := client.Sys().ListMounts()
    if err != nil {
        return nil, fmt.Errorf("failed to list mounts: %v", err)
    }

    isV2 := false

    if m, ok := mounts[mount+"/"]; ok && m.Options["version"] == "2" {
        isV2 = true
        // Convert path from secret/my-secret to secret/data/my-secret
        path = fmt.Sprintf(mount+"/data/%s", path)
    } else {
        path = fmt.Sprintf(mount+"/%s", path)
    }

    var payload map[string]interface{}

    if isV2 {
        payload = map[string]interface{}{
            "data": map[string]interface{}{
                key: value,
            },
        }
    } else {
        payload = map[string]interface{}{
            key: value,
        }
    }

    // Write the secret
    secret, err := client.Logical().Write(path, payload)
    if err != nil {
        return nil, fmt.Errorf("failed to read secret: %v", err)
    }

    if secret == nil {
        return mcp.NewToolResultText("written"), nil
    }

    // Marshal the struct to JSON (returns a []byte slice)
    jsonData, err := json.Marshal(secret.Data)
    if err != nil {
        return nil, fmt.Errorf("error marshaling JSON: %v", err)
    }

    // Convert the []byte slice to a string
    jsonString := string(jsonData)

    return mcp.NewToolResultText(jsonString), nil
}
