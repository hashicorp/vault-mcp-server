// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package sys

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/vault-mcp-server/pkg/client"
	"github.com/hashicorp/vault-mcp-server/pkg/utils"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
)

// ReadMetrics creates a tool for reading Vault telemetry metrics
func ReadMetrics(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("read_metrics",
			mcp.WithDescription("Read Vault telemetry metrics from the sys/metrics endpoint. Returns performance metrics, counters, gauges, and summaries including operations/sec, storage metrics, token operations, secret engine activity, system resource usage, and lease information. Useful for performance monitoring, capacity planning, checking lease counts, and operational diagnostics."),
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					IdempotentHint: utils.ToBoolPtr(true),
					ReadOnlyHint:   utils.ToBoolPtr(true),
				},
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return readMetricsHandler(ctx, req, logger)
		},
	}
}

func readMetricsHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling read_metrics request")

	logger.Debug("Reading Vault metrics")

	// Get Vault client from context
	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	// Query the sys/metrics endpoint (returns JSON by default)
	secret, err := vault.Logical().Read("sys/metrics")
	if err != nil {
		logger.WithError(err).Error("Failed to read metrics")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to read metrics: %v", err)), nil
	}

	if secret == nil || secret.Data == nil {
		return mcp.NewToolResultError("No metrics data returned"), nil
	}

	// Format the JSON response
	jsonData, err := json.MarshalIndent(secret.Data, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to format metrics: %v", err)), nil
	}
	resultText := string(jsonData)

	logger.WithFields(log.Fields{
		"data_length": len(resultText),
	}).Debug("Successfully retrieved metrics")

	return mcp.NewToolResultText(resultText), nil
}
