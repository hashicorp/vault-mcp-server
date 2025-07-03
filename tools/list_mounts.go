// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"vault-mcp-server/vault"
)

type Mount struct {
	Name            string `json:"name"`              // Name of the mount
	Type            string `json:"type"`              // Type of the mount (e.g., kv, kv2)
	Description     string `json:"description"`       // Description of the mount, if any
	DefaultLeaseTTL int    `json:"default_lease_ttl"` // Default lease TTL for the mount, if any
	MaxLeaseTTL     int    `json:"max_lease_ttl"`     // Max lease TTL for the mount, if any
}

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

	var results []*Mount

	for k, v := range mounts {
		e := &Mount{Name: k,
			Type:            v.Type,
			Description:     v.Description,
			DefaultLeaseTTL: v.Config.DefaultLeaseTTL,
			MaxLeaseTTL:     v.Config.MaxLeaseTTL,
		}
		results = append(results, e)
	}

	// Marshal the struct to JSON (returns a []byte slice)
	jsonData, err := json.Marshal(results)
	if err != nil {
		return nil, fmt.Errorf("error marshaling JSON: %v", err)
	}

	// Convert the []byte slice to a string
	jsonString := string(jsonData)

	return mcp.NewToolResultText(jsonString), nil
}
