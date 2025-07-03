// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package tools

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault/api"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"vault-mcp-server/vault"
)

func CreateMount() server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("create-mount",
			mcp.WithDescription("Mount a secret engine type on a Vault Server at a given path."),
			mcp.WithString("type", mcp.Required(), mcp.Enum("kv", "kv2"), mcp.Description("The type of mount. Supported: 'kv' (KV v1), 'kv2' (KV v2)")),
			mcp.WithString("path", mcp.Required(), mcp.Description("The path where the mount will be created")),
			mcp.WithString("description", mcp.DefaultString(""), mcp.Description("Optional description for the mount")),
			mcp.WithObject("options", mcp.Description("Optional mount options")),
		),
		Handler: createMountHandler,
	}
}

func createMountHandler(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	// Get the current session from context
	session := server.ClientSessionFromContext(ctx)
	if session == nil {
		return mcp.NewToolResultError("No active session"), nil
	}

	client := vault.GetVaultClient(session.SessionID())

	mountType := req.GetArguments()["type"].(string)
	path := req.GetArguments()["path"].(string)
	description := req.GetArguments()["description"].(string)
	options := req.GetArguments()["options"]

	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return nil, fmt.Errorf("failed to list mounts: %v", err)
	}

	if _, ok := mounts[path+"/"]; ok {
		return nil, fmt.Errorf("mount already exists")
	}

	payload := &api.MountInput{
		Type:        mountType,
		Description: description,
	}

	if mountType == "kv2" {
		payload.Options = make(map[string]string)
		payload.Type = "kv"
		if options != nil {
			for key, value := range options.(map[string]interface{}) {
				if s, ok := value.(string); ok {
					payload.Options[key] = s
				}
			}
		}
		payload.Options["version"] = "2"
	}

	// Create the mount
	err = client.Sys().Mount(path, payload)

	if err != nil {
		return nil, fmt.Errorf("failed to create mount: %v", err)
	}

	return mcp.NewToolResultText("mount created"), nil
}
