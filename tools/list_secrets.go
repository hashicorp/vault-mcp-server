// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"strings"
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

	mount := strings.TrimSuffix(strings.TrimPrefix(req.GetArguments()["mount"].(string), "/"), "/") // Ensure mount is trimmed of leading/trailing slash
	path := strings.TrimPrefix(req.GetArguments()["path"].(string), "/")

	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return nil, fmt.Errorf("failed to list mounts: %v", err)
	}

	if m, ok := mounts[mount+"/"]; ok && m.Options["version"] == "2" {
		// Convert path from secret/my-secret to secret/data/my-secret
		path = fmt.Sprintf(mount+"/metadata/%s", path)
	} else {
		path = fmt.Sprintf(mount+"/%s", path)
	}

	value, err := client.Logical().List(path)

	if err != nil {
		return nil, err
	}

	if value == nil {
		return mcp.NewToolResultText("path does not contain any values"), nil
	}

	data, ok := value.Data["keys"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected keys data format for list API")
	}

	// Marshal the struct to JSON (returns a []byte slice)
	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("error marshaling JSON: %v", err)
	}

	// Convert the []byte slice to a string
	jsonString := string(jsonData)

	return mcp.NewToolResultText(jsonString), nil
}
