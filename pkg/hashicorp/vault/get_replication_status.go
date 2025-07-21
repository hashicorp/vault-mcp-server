package vault

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/api"
)

// ReplicationStatus represents comprehensive replication status information
type ReplicationStatus struct {
	DRReplication          *DRReplicationStatus          `json:"dr_replication,omitempty"`
	PerformanceReplication *PerformanceReplicationStatus `json:"performance_replication,omitempty"`

	// Metadata
	Timestamp string                 `json:"timestamp"`
	Source    string                 `json:"source"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// DRReplicationStatus represents disaster recovery replication status
type DRReplicationStatus struct {
	Mode                  string                 `json:"mode"`
	ClusterID             string                 `json:"cluster_id"`
	State                 string                 `json:"state"`
	PrimaryClusterAddr    string                 `json:"primary_cluster_addr,omitempty"`
	Secondaries           []ReplicationSecondary `json:"secondaries,omitempty"`
	KnownSecondaries      []string               `json:"known_secondaries,omitempty"`
	LastDRWAL             int                    `json:"last_dr_wal"`
	LastWAL               int                    `json:"last_wal"`
	MerkleRoot            string                 `json:"merkle_root"`
	CorruptedMerkleTree   bool                   `json:"corrupted_merkle_tree"`
	LastReindexEpoch      string                 `json:"last_reindex_epoch"`
	SSCTGenerationCounter int                    `json:"ssct_generation_counter"`
}

// PerformanceReplicationStatus represents performance replication status
type PerformanceReplicationStatus struct {
	Mode                     string                 `json:"mode"`
	ClusterID                string                 `json:"cluster_id"`
	State                    string                 `json:"state"`
	PrimaryClusterAddr       string                 `json:"primary_cluster_addr,omitempty"`
	Secondaries              []ReplicationSecondary `json:"secondaries,omitempty"`
	KnownSecondaries         []string               `json:"known_secondaries,omitempty"`
	LastPerformanceWAL       int                    `json:"last_performance_wal"`
	LastWAL                  int                    `json:"last_wal"`
	MerkleRoot               string                 `json:"merkle_root"`
	CorruptedMerkleTree      bool                   `json:"corrupted_merkle_tree"`
	LastReindexEpoch         string                 `json:"last_reindex_epoch"`
	SSCTGenerationCounter    int                    `json:"ssct_generation_counter"`
	ConnectionState          string                 `json:"connection_state,omitempty"`
	KnownPrimaryClusterAddrs []string               `json:"known_primary_cluster_addrs,omitempty"`
	LastRemoteWAL            int                    `json:"last_remote_wal"`
	LastStart                string                 `json:"last_start,omitempty"`
	SecondaryID              string                 `json:"secondary_id,omitempty"`
	Primaries                []ReplicationPrimary   `json:"primaries,omitempty"`
}

// ReplicationSecondary represents a secondary node in replication
type ReplicationSecondary struct {
	NodeID                        string `json:"node_id"`
	APIAddress                    string `json:"api_address"`
	ClusterAddress                string `json:"cluster_address"`
	ConnectionStatus              string `json:"connection_status"`
	LastHeartbeat                 string `json:"last_heartbeat"`
	LastHeartbeatDurationMs       string `json:"last_heartbeat_duration_ms"`
	ClockSkewMs                   string `json:"clock_skew_ms"`
	ReplicationPrimaryCanaryAgeMs string `json:"replication_primary_canary_age_ms"`
}

// ReplicationPrimary represents a primary node in replication
type ReplicationPrimary struct {
	APIAddress                    string `json:"api_address"`
	ClusterAddress                string `json:"cluster_address"`
	ConnectionStatus              string `json:"connection_status"`
	LastHeartbeat                 string `json:"last_heartbeat"`
	LastHeartbeatDurationMs       string `json:"last_heartbeat_duration_ms"`
	ClockSkewMs                   string `json:"clock_skew_ms"`
	ReplicationPrimaryCanaryAgeMs string `json:"replication_primary_canary_age_ms"`
}

// MerkleCheckResult represents merkle tree corruption check results
type MerkleCheckResult struct {
	CorruptedRoot            bool                      `json:"corrupted_root"`
	CorruptedTreeMap         map[string]MerkleTreeInfo `json:"corrupted_tree_map"`
	LastCorruptionCheckEpoch string                    `json:"last_corruption_check_epoch"`

	// Metadata
	Timestamp string                 `json:"timestamp"`
	Source    string                 `json:"source"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// MerkleTreeInfo represents information about a merkle tree
type MerkleTreeInfo struct {
	CorruptedSubtreeRoot    bool                            `json:"corrupted_subtree_root"`
	RootHash                string                          `json:"root_hash"`
	TreeType                string                          `json:"tree_type"`
	CorruptedIndexTuplesMap map[string]MerkleCorruptionInfo `json:"corrupted_index_tuples_map"`
}

// MerkleCorruptionInfo represents corruption information for merkle tree pages
type MerkleCorruptionInfo struct {
	Corrupted bool  `json:"corrupted"`
	Subpages  []int `json:"subpages"`
}

// getReplicationStatus retrieves comprehensive replication status from Vault
func getReplicationStatus(ctx context.Context, client *api.Client) (*ReplicationStatus, error) {
	secret, err := client.Logical().Read("sys/replication/status")
	if err != nil {
		return nil, fmt.Errorf("failed to read replication status: %w", err)
	}

	status := &ReplicationStatus{
		Timestamp: getCurrentTimestamp(),
		Source:    "vault_api",
		Metadata:  make(map[string]interface{}),
	}

	if secret != nil && secret.Data != nil {
		// Parse DR replication status
		if drData, ok := secret.Data["dr"].(map[string]interface{}); ok {
			status.DRReplication = parseDRReplicationStatus(drData)
		}

		// Parse Performance replication status
		if perfData, ok := secret.Data["performance"].(map[string]interface{}); ok {
			status.PerformanceReplication = parsePerformanceReplicationStatus(perfData)
		}

		// Add metadata
		status.Metadata["has_dr_replication"] = status.DRReplication != nil
		status.Metadata["has_performance_replication"] = status.PerformanceReplication != nil

		// Health assessment
		healthStatus := "healthy"
		issues := make([]string, 0)

		if status.DRReplication != nil {
			if status.DRReplication.CorruptedMerkleTree {
				healthStatus = "unhealthy"
				issues = append(issues, "DR merkle tree corrupted")
			}
			if status.DRReplication.State != "running" && status.DRReplication.Mode != "disabled" {
				healthStatus = "degraded"
				issues = append(issues, fmt.Sprintf("DR replication state: %s", status.DRReplication.State))
			}
		}

		if status.PerformanceReplication != nil {
			if status.PerformanceReplication.CorruptedMerkleTree {
				healthStatus = "unhealthy"
				issues = append(issues, "Performance merkle tree corrupted")
			}
			if status.PerformanceReplication.State != "running" && status.PerformanceReplication.State != "stream-wals" && status.PerformanceReplication.Mode != "disabled" {
				healthStatus = "degraded"
				issues = append(issues, fmt.Sprintf("Performance replication state: %s", status.PerformanceReplication.State))
			}
		}

		status.Metadata["replication_health"] = healthStatus
		if len(issues) > 0 {
			status.Metadata["health_issues"] = issues
		}
	}

	return status, nil
}

// getMerkleCheckResult retrieves merkle tree corruption check results
func getMerkleCheckResult(ctx context.Context, client *api.Client) (*MerkleCheckResult, error) {
	secret, err := client.Logical().Write("sys/replication/merkle-check", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to perform merkle check: %w", err)
	}

	result := &MerkleCheckResult{
		Timestamp: getCurrentTimestamp(),
		Source:    "vault_api",
		Metadata:  make(map[string]interface{}),
	}

	if secret != nil && secret.Data != nil {
		if reportData, ok := secret.Data["merkle_corruption_report"].(map[string]interface{}); ok {
			if v, ok := reportData["corrupted_root"].(bool); ok {
				result.CorruptedRoot = v
			}
			if v, ok := reportData["last_corruption_check_epoch"].(string); ok {
				result.LastCorruptionCheckEpoch = v
			}
			if treeMap, ok := reportData["corrupted_tree_map"].(map[string]interface{}); ok {
				result.CorruptedTreeMap = make(map[string]MerkleTreeInfo)
				for treeID, treeData := range treeMap {
					if treeInfo, ok := treeData.(map[string]interface{}); ok {
						result.CorruptedTreeMap[treeID] = parseMerkleTreeInfo(treeInfo)
					}
				}
			}
		}

		// Add metadata
		result.Metadata["has_corruption"] = result.CorruptedRoot || len(result.CorruptedTreeMap) > 0
		corruptionCount := 0
		for _, tree := range result.CorruptedTreeMap {
			if tree.CorruptedSubtreeRoot {
				corruptionCount++
			}
		}
		result.Metadata["corruption_count"] = corruptionCount
	}

	return result, nil
}

// Helper functions for parsing replication data would go here...
// (parseDRReplicationStatus, parsePerformanceReplicationStatus, parseMerkleTreeInfo, etc.)

// parseDRReplicationStatus parses DR replication status data
func parseDRReplicationStatus(data map[string]interface{}) *DRReplicationStatus {
	status := &DRReplicationStatus{}

	if v, ok := data["mode"].(string); ok {
		status.Mode = v
	}
	if v, ok := data["cluster_id"].(string); ok {
		status.ClusterID = v
	}
	if v, ok := data["state"].(string); ok {
		status.State = v
	}
	// Add more field parsing as needed...

	return status
}

// parsePerformanceReplicationStatus parses performance replication status data
func parsePerformanceReplicationStatus(data map[string]interface{}) *PerformanceReplicationStatus {
	status := &PerformanceReplicationStatus{}

	if v, ok := data["mode"].(string); ok {
		status.Mode = v
	}
	if v, ok := data["cluster_id"].(string); ok {
		status.ClusterID = v
	}
	if v, ok := data["state"].(string); ok {
		status.State = v
	}
	// Add more field parsing as needed...

	return status
}

// parseMerkleTreeInfo parses merkle tree information
func parseMerkleTreeInfo(data map[string]interface{}) MerkleTreeInfo {
	info := MerkleTreeInfo{}

	if v, ok := data["corrupted_subtree_root"].(bool); ok {
		info.CorruptedSubtreeRoot = v
	}
	if v, ok := data["root_hash"].(string); ok {
		info.RootHash = v
	}
	if v, ok := data["tree_type"].(string); ok {
		info.TreeType = v
	}
	// Add more field parsing as needed...

	return info
}
