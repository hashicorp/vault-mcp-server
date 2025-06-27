package tools

import (
    "context"
    "encoding/json"
    "fmt"
    "github.com/mark3labs/mcp-go/mcp"
    "github.com/mark3labs/mcp-go/server"
    "vault-mcp-server/vault"
)

func ReadSecrets() server.ServerTool {
    return server.ServerTool{
        Tool: mcp.NewTool("read-secret",
            mcp.WithString("mount", mcp.Required(), mcp.Description("The mount path (e.g., 'secrets' or 'kv')")),
            mcp.WithString("path", mcp.Required(), mcp.Description("The full path to write the secret to, excluding the mount (e.g., 'foo/bar')")),
        ),
        Handler: handler,
    }
}

func handler(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
    // Get the current session from context
    session := server.ClientSessionFromContext(ctx)
    if session == nil {
        return mcp.NewToolResultError("No active session"), nil
    }

    client := vault.GetVaultClient(session.SessionID())

    mount := req.GetArguments()["mount"].(string)
    path := req.GetArguments()["path"].(string)

    mounts, err := client.Sys().ListMounts()
    if err != nil {
        return nil, fmt.Errorf("failed to list mounts: %v", err)
    }

    isV2 := false

    if m, ok := mounts[mount+"/"]; ok && m.Options["version"] == "2" {
        isV2 = true
        // Convert path from secret/my-secret to secret/data/my-secret
        path = fmt.Sprintf(mount+"/data/%s", path)
    }

    // Read the secret
    secret, err := client.Logical().Read(path)
    if err != nil {
        return nil, fmt.Errorf("failed to read secret: %v", err)
    }

    if secret == nil {
        return nil, fmt.Errorf("no secret found at path: %s", path)
    }

    // Handle the data structure differently for v1 and v2
    var value interface{}

    if isV2 {
        // V2 API structure: secret.Data["data"] contains the actual key-value pairs
        data, ok := secret.Data["data"].(map[string]interface{})
        if !ok {
            return nil, fmt.Errorf("unexpected secret data format for v2 API")
        }
        value = data
    } else {
        // V1 API structure: secret.Data directly contains the key-value pairs
        value = secret.Data
    }

    // Marshal the struct to JSON (returns a []byte slice)
    jsonData, err := json.Marshal(value)
    if err != nil {
        return nil, fmt.Errorf("Error marshaling JSON")
    }

    // Convert the []byte slice to a string
    jsonString := string(jsonData)

    return mcp.NewToolResultText(fmt.Sprintf("%v", jsonString)), nil
}
