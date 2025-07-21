// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
)

// GetSealStatus creates a tool for getting Vault seal status
func GetSealStatus(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("get_seal_status",
			mcp.WithDescription("Get detailed seal status information from Vault"),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return getSealStatusHandler(ctx, req, logger)
		},
	}
}

func getSealStatusHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling get_seal_status request")

	// Get Vault client from context
	client, err := GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	// Get seal status from Vault
	sealStatus, err := client.Sys().SealStatus()
	if err != nil {
		logger.WithError(err).Error("Failed to get seal status")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get seal status: %v", err)), nil
	}

	status := &SealStatus{
		Type:         sealStatus.Type,
		Initialized:  sealStatus.Initialized,
		Sealed:       sealStatus.Sealed,
		T:            sealStatus.T,
		N:            sealStatus.N,
		Progress:     sealStatus.Progress,
		Nonce:        sealStatus.Nonce,
		Version:      sealStatus.Version,
		BuildDate:    sealStatus.BuildDate,
		Migration:    sealStatus.Migration,
		ClusterName:  sealStatus.ClusterName,
		ClusterID:    sealStatus.ClusterID,
		RecoverySeal: sealStatus.RecoverySeal,
		StorageType:  sealStatus.StorageType,
	}

	// Marshal to JSON
	jsonData, err := json.Marshal(status)
	if err != nil {
		logger.WithError(err).Error("Failed to marshal seal status to JSON")
		return mcp.NewToolResultError(fmt.Sprintf("Error marshaling JSON: %v", err)), nil
	}

	logger.WithFields(log.Fields{
		"sealed":      status.Sealed,
		"initialized": status.Initialized,
		"type":        status.Type,
	}).Debug("Successfully retrieved seal status")

	return mcp.NewToolResultText(string(jsonData)), nil
}
