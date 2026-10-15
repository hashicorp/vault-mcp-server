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

type ClusterHealthDetail struct {
	HAStatus          *HAStatusInfo          `json:"ha_status,omitempty"`
	AutopilotState    *AutopilotStateInfo    `json:"autopilot_state,omitempty"`
	AutopilotConfig   *AutopilotConfigInfo   `json:"autopilot_config,omitempty"`
	SealBackendStatus *SealBackendStatusInfo `json:"seal_backend_status,omitempty"`
}

type HAStatusInfo struct {
	Nodes             []HANode `json:"nodes,omitempty"`
	LeaderAddress     string   `json:"leader_address,omitempty"`
	LeaderClusterAddr string   `json:"leader_cluster_address,omitempty"`
}

type HANode struct {
	Hostname       string `json:"hostname,omitempty"`
	APIAddress     string `json:"api_address,omitempty"`
	ClusterAddr    string `json:"cluster_address,omitempty"`
	ActiveNode     bool   `json:"active_node"`
	LastEcho       string `json:"last_echo,omitempty"`
	Version        string `json:"version,omitempty"`
	UpgradeVer     string `json:"upgrade_version,omitempty"`
	RedundancyZone string `json:"redundancy_zone,omitempty"`
}

type AutopilotStateInfo struct {
	Healthy                    bool                       `json:"healthy"`
	FailureTolerance           int                        `json:"failure_tolerance"`
	OptimisticFailureTolerance int                        `json:"optimistic_failure_tolerance"`
	Servers                    map[string]*ServerStatus   `json:"servers,omitempty"`
	Leader                     string                     `json:"leader,omitempty"`
	Voters                     []string                   `json:"voters,omitempty"`
	NonVoters                  []string                   `json:"non_voters,omitempty"`
	RedundancyZones            map[string]*RedundancyZone `json:"redundancy_zones,omitempty"`
	Upgrade                    *UpgradeInfo               `json:"upgrade,omitempty"`
}

type ServerStatus struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Address        string `json:"address"`
	NodeStatus     string `json:"node_status"`
	Healthy        bool   `json:"healthy"`
	LastContact    string `json:"last_contact,omitempty"`
	LastTerm       uint64 `json:"last_term,omitempty"`
	LastIndex      uint64 `json:"last_index,omitempty"`
	Version        string `json:"version,omitempty"`
	UpgradeVersion string `json:"upgrade_version,omitempty"`
	RedundancyZone string `json:"redundancy_zone,omitempty"`
	NodeType       string `json:"node_type,omitempty"`
}

type RedundancyZone struct {
	Servers          []string `json:"servers,omitempty"`
	Voters           []string `json:"voters,omitempty"`
	FailureTolerance int      `json:"failure_tolerance"`
}

type UpgradeInfo struct {
	Status                 string                      `json:"status,omitempty"`
	TargetVersion          string                      `json:"target_version,omitempty"`
	TargetVersionVoters    []string                    `json:"target_version_voters,omitempty"`
	TargetVersionNonVoters []string                    `json:"target_version_non_voters,omitempty"`
	OtherVersionVoters     []string                    `json:"other_version_voters,omitempty"`
	OtherVersionNonVoters  []string                    `json:"other_version_non_voters,omitempty"`
	RedundancyZones        map[string]*UpgradeZoneInfo `json:"redundancy_zones,omitempty"`
}

type UpgradeZoneInfo struct {
	TargetVersionVoters    []string `json:"target_version_voters,omitempty"`
	TargetVersionNonVoters []string `json:"target_version_non_voters,omitempty"`
	OtherVersionVoters     []string `json:"other_version_voters,omitempty"`
	OtherVersionNonVoters  []string `json:"other_version_non_voters,omitempty"`
}

type AutopilotConfigInfo struct {
	CleanupDeadServers             bool   `json:"cleanup_dead_servers"`
	LastContactThreshold           string `json:"last_contact_threshold,omitempty"`
	DeadServerLastContactThreshold string `json:"dead_server_last_contact_threshold,omitempty"`
	MaxTrailingLogs                uint64 `json:"max_trailing_logs,omitempty"`
	MinQuorum                      uint64 `json:"min_quorum,omitempty"`
	ServerStabilizationTime        string `json:"server_stabilization_time,omitempty"`
	DisableUpgradeMigration        bool   `json:"disable_upgrade_migration"`
}

type SealBackendStatusInfo struct {
	Type    string                 `json:"type,omitempty"`
	Healthy bool                   `json:"healthy"`
	Details map[string]interface{} `json:"details,omitempty"`
}

// ReadClusterHealth creates a tool for reading comprehensive cluster health information
func ReadClusterHealth(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("read_cluster_health",
			mcp.WithDescription("Read comprehensive cluster health information including HA status (nodes, leader), Raft autopilot state (server health, failure tolerance, redundancy zones), autopilot configuration (cleanup settings, thresholds), and seal backend status (KMS/HSM health). Provides detailed insights beyond basic sys/health endpoint for monitoring cluster quorum, node lifecycle, and external dependency health."),
			mcp.WithToolAnnotation(
				mcp.ToolAnnotation{
					IdempotentHint: utils.ToBoolPtr(true),
					ReadOnlyHint:   utils.ToBoolPtr(true),
				},
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return readClusterHealthHandler(ctx, req, logger)
		},
	}
}

func readClusterHealthHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling read_cluster_health request")

	// Get Vault client from context
	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	result := &ClusterHealthDetail{}

	// Read HA status
	logger.Debug("Reading HA status")
	haStatus, err := vault.Logical().Read("sys/ha-status")
	if err != nil {
		logger.WithError(err).Warn("Failed to read HA status")
	} else if haStatus != nil && haStatus.Data != nil {
		result.HAStatus = parseHAStatus(haStatus.Data)
	}

	// Read Raft autopilot state (only for integrated storage)
	logger.Debug("Reading Raft autopilot state")
	autopilotState, err := vault.Logical().Read("sys/storage/raft/autopilot/state")
	if err != nil {
		logger.WithError(err).Debug("Failed to read autopilot state (may not be using integrated storage)")
	} else if autopilotState != nil && autopilotState.Data != nil {
		result.AutopilotState = parseAutopilotState(autopilotState.Data)
	}

	// Read Raft autopilot configuration
	logger.Debug("Reading Raft autopilot configuration")
	autopilotConfig, err := vault.Logical().Read("sys/storage/raft/autopilot/configuration")
	if err != nil {
		logger.WithError(err).Debug("Failed to read autopilot configuration (may not be using integrated storage)")
	} else if autopilotConfig != nil && autopilotConfig.Data != nil {
		result.AutopilotConfig = parseAutopilotConfig(autopilotConfig.Data)
	}

	// Read seal backend status
	logger.Debug("Reading seal backend status")
	sealStatus, err := vault.Logical().Read("sys/seal-backend-status")
	if err != nil {
		logger.WithError(err).Debug("Failed to read seal backend status")
	} else if sealStatus != nil && sealStatus.Data != nil {
		result.SealBackendStatus = parseSealBackendStatus(sealStatus.Data)
	}

	// Marshal to JSON for pretty output
	resultJSON, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		logger.WithError(err).Error("Failed to marshal cluster health")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to format cluster health: %v", err)), nil
	}

	logger.WithFields(log.Fields{
		"has_ha_status":           result.HAStatus != nil,
		"has_autopilot_state":     result.AutopilotState != nil,
		"has_autopilot_config":    result.AutopilotConfig != nil,
		"has_seal_backend_status": result.SealBackendStatus != nil,
	}).Debug("Successfully read cluster health")

	return mcp.NewToolResultText(string(resultJSON)), nil
}

func parseHAStatus(data map[string]interface{}) *HAStatusInfo {
	info := &HAStatusInfo{}

	if nodes, ok := data["nodes"].([]interface{}); ok {
		info.Nodes = make([]HANode, 0, len(nodes))
		for _, n := range nodes {
			if nodeMap, ok := n.(map[string]interface{}); ok {
				node := HANode{}
				if hostname, ok := nodeMap["hostname"].(string); ok {
					node.Hostname = hostname
				}
				if apiAddr, ok := nodeMap["api_address"].(string); ok {
					node.APIAddress = apiAddr
				}
				if clusterAddr, ok := nodeMap["cluster_address"].(string); ok {
					node.ClusterAddr = clusterAddr
				}
				if active, ok := nodeMap["active_node"].(bool); ok {
					node.ActiveNode = active
				}
				if lastEcho, ok := nodeMap["last_echo"].(string); ok {
					node.LastEcho = lastEcho
				}
				if version, ok := nodeMap["version"].(string); ok {
					node.Version = version
				}
				if upgradeVer, ok := nodeMap["upgrade_version"].(string); ok {
					node.UpgradeVer = upgradeVer
				}
				if zone, ok := nodeMap["redundancy_zone"].(string); ok {
					node.RedundancyZone = zone
				}
				info.Nodes = append(info.Nodes, node)
			}
		}
	}

	if leader, ok := data["leader_address"].(string); ok {
		info.LeaderAddress = leader
	}
	if leaderCluster, ok := data["leader_cluster_address"].(string); ok {
		info.LeaderClusterAddr = leaderCluster
	}

	return info
}

func parseAutopilotState(data map[string]interface{}) *AutopilotStateInfo {
	info := &AutopilotStateInfo{}

	if healthy, ok := data["healthy"].(bool); ok {
		info.Healthy = healthy
	}
	if ft, ok := data["failure_tolerance"].(float64); ok {
		info.FailureTolerance = int(ft)
	}
	if oft, ok := data["optimistic_failure_tolerance"].(float64); ok {
		info.OptimisticFailureTolerance = int(oft)
	}
	if leader, ok := data["leader"].(string); ok {
		info.Leader = leader
	}

	// Parse servers
	if servers, ok := data["servers"].(map[string]interface{}); ok {
		info.Servers = make(map[string]*ServerStatus)
		for id, s := range servers {
			if serverMap, ok := s.(map[string]interface{}); ok {
				info.Servers[id] = parseServerStatus(serverMap)
			}
		}
	}

	// Parse voters
	if voters, ok := data["voters"].([]interface{}); ok {
		info.Voters = make([]string, 0, len(voters))
		for _, v := range voters {
			if voter, ok := v.(string); ok {
				info.Voters = append(info.Voters, voter)
			}
		}
	}

	// Parse non-voters
	if nonVoters, ok := data["non_voters"].([]interface{}); ok {
		info.NonVoters = make([]string, 0, len(nonVoters))
		for _, nv := range nonVoters {
			if nonVoter, ok := nv.(string); ok {
				info.NonVoters = append(info.NonVoters, nonVoter)
			}
		}
	}

	// Parse redundancy zones
	if zones, ok := data["redundancy_zones"].(map[string]interface{}); ok {
		info.RedundancyZones = make(map[string]*RedundancyZone)
		for zoneName, z := range zones {
			if zoneMap, ok := z.(map[string]interface{}); ok {
				info.RedundancyZones[zoneName] = parseRedundancyZone(zoneMap)
			}
		}
	}

	// Parse upgrade info
	if upgrade, ok := data["upgrade"].(map[string]interface{}); ok {
		info.Upgrade = parseUpgradeInfo(upgrade)
	}

	return info
}

func parseServerStatus(data map[string]interface{}) *ServerStatus {
	status := &ServerStatus{}

	if id, ok := data["id"].(string); ok {
		status.ID = id
	}
	if name, ok := data["name"].(string); ok {
		status.Name = name
	}
	if address, ok := data["address"].(string); ok {
		status.Address = address
	}
	if nodeStatus, ok := data["node_status"].(string); ok {
		status.NodeStatus = nodeStatus
	}
	if healthy, ok := data["healthy"].(bool); ok {
		status.Healthy = healthy
	}
	if lastContact, ok := data["last_contact"].(string); ok {
		status.LastContact = lastContact
	}
	if lastTerm, ok := data["last_term"].(float64); ok {
		status.LastTerm = uint64(lastTerm)
	}
	if lastIndex, ok := data["last_index"].(float64); ok {
		status.LastIndex = uint64(lastIndex)
	}
	if version, ok := data["version"].(string); ok {
		status.Version = version
	}
	if upgradeVersion, ok := data["upgrade_version"].(string); ok {
		status.UpgradeVersion = upgradeVersion
	}
	if zone, ok := data["redundancy_zone"].(string); ok {
		status.RedundancyZone = zone
	}
	if nodeType, ok := data["node_type"].(string); ok {
		status.NodeType = nodeType
	}

	return status
}

func parseRedundancyZone(data map[string]interface{}) *RedundancyZone {
	zone := &RedundancyZone{}

	if servers, ok := data["servers"].([]interface{}); ok {
		zone.Servers = make([]string, 0, len(servers))
		for _, s := range servers {
			if server, ok := s.(string); ok {
				zone.Servers = append(zone.Servers, server)
			}
		}
	}

	if voters, ok := data["voters"].([]interface{}); ok {
		zone.Voters = make([]string, 0, len(voters))
		for _, v := range voters {
			if voter, ok := v.(string); ok {
				zone.Voters = append(zone.Voters, voter)
			}
		}
	}

	if ft, ok := data["failure_tolerance"].(float64); ok {
		zone.FailureTolerance = int(ft)
	}

	return zone
}

func parseUpgradeInfo(data map[string]interface{}) *UpgradeInfo {
	info := &UpgradeInfo{}

	if status, ok := data["status"].(string); ok {
		info.Status = status
	}
	if targetVer, ok := data["target_version"].(string); ok {
		info.TargetVersion = targetVer
	}

	// Helper function to parse string arrays
	parseStringArray := func(key string) []string {
		if arr, ok := data[key].([]interface{}); ok {
			result := make([]string, 0, len(arr))
			for _, item := range arr {
				if str, ok := item.(string); ok {
					result = append(result, str)
				}
			}
			return result
		}
		return nil
	}

	info.TargetVersionVoters = parseStringArray("target_version_voters")
	info.TargetVersionNonVoters = parseStringArray("target_version_non_voters")
	info.OtherVersionVoters = parseStringArray("other_version_voters")
	info.OtherVersionNonVoters = parseStringArray("other_version_non_voters")

	// Parse redundancy zones
	if zones, ok := data["redundancy_zones"].(map[string]interface{}); ok {
		info.RedundancyZones = make(map[string]*UpgradeZoneInfo)
		for zoneName, z := range zones {
			if zoneMap, ok := z.(map[string]interface{}); ok {
				zoneInfo := &UpgradeZoneInfo{}

				parseZoneStringArray := func(key string) []string {
					if arr, ok := zoneMap[key].([]interface{}); ok {
						result := make([]string, 0, len(arr))
						for _, item := range arr {
							if str, ok := item.(string); ok {
								result = append(result, str)
							}
						}
						return result
					}
					return nil
				}

				zoneInfo.TargetVersionVoters = parseZoneStringArray("target_version_voters")
				zoneInfo.TargetVersionNonVoters = parseZoneStringArray("target_version_non_voters")
				zoneInfo.OtherVersionVoters = parseZoneStringArray("other_version_voters")
				zoneInfo.OtherVersionNonVoters = parseZoneStringArray("other_version_non_voters")

				info.RedundancyZones[zoneName] = zoneInfo
			}
		}
	}

	return info
}

func parseAutopilotConfig(data map[string]interface{}) *AutopilotConfigInfo {
	config := &AutopilotConfigInfo{}

	if cleanup, ok := data["cleanup_dead_servers"].(bool); ok {
		config.CleanupDeadServers = cleanup
	}
	if threshold, ok := data["last_contact_threshold"].(string); ok {
		config.LastContactThreshold = threshold
	}
	if deadThreshold, ok := data["dead_server_last_contact_threshold"].(string); ok {
		config.DeadServerLastContactThreshold = deadThreshold
	}
	if maxLogs, ok := data["max_trailing_logs"].(float64); ok {
		config.MaxTrailingLogs = uint64(maxLogs)
	}
	if minQuorum, ok := data["min_quorum"].(float64); ok {
		config.MinQuorum = uint64(minQuorum)
	}
	if stabilization, ok := data["server_stabilization_time"].(string); ok {
		config.ServerStabilizationTime = stabilization
	}
	if disableUpgrade, ok := data["disable_upgrade_migration"].(bool); ok {
		config.DisableUpgradeMigration = disableUpgrade
	}

	return config
}

func parseSealBackendStatus(data map[string]interface{}) *SealBackendStatusInfo {
	info := &SealBackendStatusInfo{}

	if sealType, ok := data["type"].(string); ok {
		info.Type = sealType
	}
	if healthy, ok := data["healthy"].(bool); ok {
		info.Healthy = healthy
	}

	// Capture any additional details
	info.Details = make(map[string]interface{})
	for key, value := range data {
		if key != "type" && key != "healthy" {
			info.Details[key] = value
		}
	}

	return info
}
