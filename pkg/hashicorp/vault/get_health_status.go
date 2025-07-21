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

// GetHealthStatus creates a tool for getting Vault health status
func GetHealthStatus(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("get_health_status",
			mcp.WithDescription("Get health status of Vault cluster including initialization, sealing status, and HA mode"),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return getHealthStatusHandler(ctx, req, logger)
		},
	}
}

func getHealthStatusHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling get_health_status request")

	// Get Vault client from context
	client, err := GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	// Get health status from Vault
	health, err := client.Sys().Health()
	if err != nil {
		logger.WithError(err).Error("Failed to get health status")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get health status: %v", err)), nil
	}

	healthStatus := &HealthStatus{
		Initialized:                health.Initialized,
		Sealed:                     health.Sealed,
		Standby:                    health.Standby,
		PerformanceStandby:         health.PerformanceStandby,
		ReplicationPerformanceMode: health.ReplicationPerformanceMode,
		ReplicationDRMode:          health.ReplicationDRMode,
		ServerTimeUTC:              health.ServerTimeUTC,
		Version:                    health.Version,
		ClusterName:                health.ClusterName,
		ClusterID:                  health.ClusterID,
	}

	// Marshal to JSON
	jsonData, err := json.Marshal(healthStatus)
	if err != nil {
		logger.WithError(err).Error("Failed to marshal health status to JSON")
		return mcp.NewToolResultError(fmt.Sprintf("Error marshaling JSON: %v", err)), nil
	}

	logger.WithFields(log.Fields{
		"initialized": healthStatus.Initialized,
		"sealed":      healthStatus.Sealed,
		"standby":     healthStatus.Standby,
		"version":     healthStatus.Version,
	}).Debug("Successfully retrieved health status")

	return mcp.NewToolResultText(string(jsonData)), nil
}
