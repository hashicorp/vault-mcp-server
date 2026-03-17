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

type ReplicationStatusDetail struct {
	Mode        string                 `json:"mode"`                  // Replication mode (primary, secondary, disabled)
	ClusterID   string                 `json:"cluster_id,omitempty"`  // Cluster ID
	Performance *ReplicationModeStatus `json:"performance,omitempty"` // Performance replication status
	DR          *ReplicationModeStatus `json:"dr,omitempty"`          // DR replication status
}

type ReplicationModeStatus struct {
	Mode               string   `json:"mode"`                           // Mode for this replication type (primary, secondary, disabled)
	ClusterID          string   `json:"cluster_id,omitempty"`           // Cluster ID
	PrimaryClusterAddr string   `json:"primary_cluster_addr,omitempty"` // Primary cluster address
	KnownSecondaries   []string `json:"known_secondaries,omitempty"`    // List of known secondaries
	State              string   `json:"state,omitempty"`                // Replication state (stream-wals, merkle-sync, etc)
	ConnectionState    string   `json:"connection_state,omitempty"`     // Connection state (ready, transient_failure, etc)
	LastWAL            uint64   `json:"last_wal,omitempty"`             // Last WAL index
	MerkleRoot         string   `json:"merkle_root,omitempty"`          // Current merkle root
	LastRemoteWAL      uint64   `json:"last_remote_wal,omitempty"`      // Last remote WAL (for secondaries)
	SecondaryID        string   `json:"secondary_id,omitempty"`         // Secondary ID
}

// ReadReplicationStatus creates a tool for reading Vault replication status
func ReadReplicationStatus(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("read_replication_status",
			mcp.WithDescription("Read detailed replication status for both Performance and DR replication. Returns cluster IDs, replication modes, connection states, WAL indexes, merkle tree status, and known secondaries. Useful for diagnosing replication health and lag."),
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					IdempotentHint: utils.ToBoolPtr(true),
					ReadOnlyHint:   utils.ToBoolPtr(true),
				},
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return readReplicationStatusHandler(ctx, req, logger)
		},
	}
}

func readReplicationStatusHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling read_replication_status request")

	// Get Vault client from context
	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	// Read replication status using logical client
	secret, err := vault.Logical().Read("sys/replication/status")
	if err != nil {
		logger.WithError(err).Error("Failed to read replication status")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to read replication status: %v", err)), nil
	}

	if secret == nil || secret.Data == nil {
		logger.Warn("No replication status data returned")
		return mcp.NewToolResultError("No replication status data available"), nil
	}

	// Extract mode at top level
	mode, _ := secret.Data["mode"].(string)

	result := &ReplicationStatusDetail{
		Mode: mode,
	}

	// Extract cluster_id if present at top level
	if clusterID, ok := secret.Data["cluster_id"].(string); ok {
		result.ClusterID = clusterID
	}

	// Parse performance replication data
	if perfData, ok := secret.Data["performance"].(map[string]interface{}); ok {
		result.Performance = parseReplicationModeStatus(perfData)
	}

	// Parse DR replication data
	if drData, ok := secret.Data["dr"].(map[string]interface{}); ok {
		result.DR = parseReplicationModeStatus(drData)
	}

	// Marshal to JSON for pretty output
	resultJSON, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		logger.WithError(err).Error("Failed to marshal replication status")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to format replication status: %v", err)), nil
	}

	logger.WithFields(log.Fields{
		"mode":            mode,
		"has_performance": result.Performance != nil,
		"has_dr":          result.DR != nil,
	}).Debug("Successfully read replication status")

	return mcp.NewToolResultText(string(resultJSON)), nil
}

func parseReplicationModeStatus(data map[string]interface{}) *ReplicationModeStatus {
	status := &ReplicationModeStatus{}

	if mode, ok := data["mode"].(string); ok {
		status.Mode = mode
	}

	if clusterID, ok := data["cluster_id"].(string); ok {
		status.ClusterID = clusterID
	}

	if primaryAddr, ok := data["primary_cluster_addr"].(string); ok {
		status.PrimaryClusterAddr = primaryAddr
	}

	if state, ok := data["state"].(string); ok {
		status.State = state
	}

	if connState, ok := data["connection_state"].(string); ok {
		status.ConnectionState = connState
	}

	if lastWAL, ok := data["last_wal"].(float64); ok {
		status.LastWAL = uint64(lastWAL)
	}

	if merkleRoot, ok := data["merkle_root"].(string); ok {
		status.MerkleRoot = merkleRoot
	}

	if lastRemoteWAL, ok := data["last_remote_wal"].(float64); ok {
		status.LastRemoteWAL = uint64(lastRemoteWAL)
	}

	if secondaryID, ok := data["secondary_id"].(string); ok {
		status.SecondaryID = secondaryID
	}

	// Parse known_secondaries array
	if knownSecondaries, ok := data["known_secondaries"].([]interface{}); ok {
		for _, sec := range knownSecondaries {
			if secStr, ok := sec.(string); ok {
				status.KnownSecondaries = append(status.KnownSecondaries, secStr)
			}
		}
	}

	return status
}
