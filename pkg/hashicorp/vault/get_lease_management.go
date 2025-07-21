package vault

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/api"
)

// LeaseInfo represents lease management information
type LeaseInfo struct {
	LeaseID         string `json:"lease_id"`
	Renewable       bool   `json:"renewable"`
	LeaseDuration   int    `json:"lease_duration"`
	TTL             int    `json:"ttl"`
	IssueTime       string `json:"issue_time,omitempty"`
	ExpireTime      string `json:"expire_time,omitempty"`
	LastRenewalTime string `json:"last_renewal_time,omitempty"`
	Path            string `json:"path,omitempty"`

	// Metadata
	Timestamp string                 `json:"timestamp"`
	Source    string                 `json:"source"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// LeaseCountsInfo represents lease count information
type LeaseCountsInfo struct {
	TotalLeases       int            `json:"total_leases"`
	IrrevocableLeases int            `json:"irrevocable_leases"`
	LeasesByMount     map[string]int `json:"leases_by_mount"`
	LeasesByType      map[string]int `json:"leases_by_type"`

	// Metadata
	Timestamp string                 `json:"timestamp"`
	Source    string                 `json:"source"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// LeaseTidyStatus represents lease tidy operation status
type LeaseTidyStatus struct {
	TidyInProgress    bool   `json:"tidy_in_progress"`
	LastTidyOperation string `json:"last_tidy_operation,omitempty"`
	LeasesRevoked     int    `json:"leases_revoked"`
	LeasesProcessed   int    `json:"leases_processed"`

	// Metadata
	Timestamp string                 `json:"timestamp"`
	Source    string                 `json:"source"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// TokenCapabilities represents token capability information
type TokenCapabilities struct {
	Token        string              `json:"token"`
	Capabilities map[string][]string `json:"capabilities"`

	// Metadata
	Timestamp string                 `json:"timestamp"`
	Source    string                 `json:"source"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// getLeaseCounts retrieves lease count information from Vault
func getLeaseCounts(ctx context.Context, client *api.Client) (*LeaseCountsInfo, error) {
	// Get lease counts - this might not be available in all Vault versions
	secret, err := client.Logical().Read("sys/leases/count")
	if err != nil {
		// Try alternative endpoint for lease information
		return getAlternativeLeaseInfo(ctx, client)
	}

	info := &LeaseCountsInfo{
		LeasesByMount: make(map[string]int),
		LeasesByType:  make(map[string]int),
		Timestamp:     getCurrentTimestamp(),
		Source:        "vault_api",
		Metadata:      make(map[string]interface{}),
	}

	if secret != nil && secret.Data != nil {
		if v, ok := secret.Data["total"].(int); ok {
			info.TotalLeases = v
		}
		if v, ok := secret.Data["irrevocable"].(int); ok {
			info.IrrevocableLeases = v
		}
		if mountData, ok := secret.Data["by_mount"].(map[string]interface{}); ok {
			for mount, count := range mountData {
				if countInt, ok := count.(int); ok {
					info.LeasesByMount[mount] = countInt
				}
			}
		}

		// Add metadata
		info.Metadata["has_irrevocable_leases"] = info.IrrevocableLeases > 0
		info.Metadata["irrevocable_percentage"] = 0.0
		if info.TotalLeases > 0 {
			info.Metadata["irrevocable_percentage"] = float64(info.IrrevocableLeases) / float64(info.TotalLeases) * 100
		}
		info.Metadata["mount_count"] = len(info.LeasesByMount)
	}

	return info, nil
}

// getAlternativeLeaseInfo tries alternative methods to get lease information
func getAlternativeLeaseInfo(ctx context.Context, client *api.Client) (*LeaseCountsInfo, error) {
	info := &LeaseCountsInfo{
		LeasesByMount: make(map[string]int),
		LeasesByType:  make(map[string]int),
		Timestamp:     getCurrentTimestamp(),
		Source:        "vault_api_alternative",
		Metadata:      make(map[string]interface{}),
	}

	// Try to get irrevocable lease list
	secret, err := client.Logical().List("sys/leases/irrevocable")
	if err == nil && secret != nil && secret.Data != nil {
		if keys, ok := secret.Data["keys"].([]interface{}); ok {
			info.IrrevocableLeases = len(keys)
			info.Metadata["has_irrevocable_leases"] = info.IrrevocableLeases > 0
		}
	}

	// Add metadata for alternative collection
	info.Metadata["collection_method"] = "alternative"
	info.Metadata["limited_data"] = true

	return info, nil
}

// getLeaseTidyStatus retrieves lease tidy operation status
func getLeaseTidyStatus(ctx context.Context, client *api.Client) (*LeaseTidyStatus, error) {
	// Note: There may not be a direct status endpoint, so we create a basic status
	status := &LeaseTidyStatus{
		Timestamp: getCurrentTimestamp(),
		Source:    "vault_api",
		Metadata:  make(map[string]interface{}),
	}

	// This is a basic implementation - the actual API might be different
	status.TidyInProgress = false
	status.Metadata["tidy_available"] = true
	status.Metadata["manual_tidy_required"] = true

	return status, nil
}

// getTokenCapabilities retrieves token capabilities for specified paths
func getTokenCapabilities(ctx context.Context, client *api.Client, token string, paths []string) (*TokenCapabilities, error) {
	if token == "" {
		return nil, fmt.Errorf("token is required")
	}

	capabilities := &TokenCapabilities{
		Token:        token,
		Capabilities: make(map[string][]string),
		Timestamp:    getCurrentTimestamp(),
		Source:       "vault_api",
		Metadata:     make(map[string]interface{}),
	}

	// Prepare the request payload
	payload := map[string]interface{}{
		"token": token,
		"paths": paths,
	}

	secret, err := client.Logical().Write("sys/capabilities", payload)
	if err != nil {
		return nil, fmt.Errorf("failed to get token capabilities: %w", err)
	}

	if secret != nil && secret.Data != nil {
		// Parse capabilities for each path
		for _, path := range paths {
			if caps, ok := secret.Data[path].([]interface{}); ok {
				capStrings := make([]string, 0, len(caps))
				for _, cap := range caps {
					if capStr, ok := cap.(string); ok {
						capStrings = append(capStrings, capStr)
					}
				}
				capabilities.Capabilities[path] = capStrings
			}
		}

		// Also check for generic capabilities field
		if caps, ok := secret.Data["capabilities"].([]interface{}); ok && len(paths) == 1 {
			capStrings := make([]string, 0, len(caps))
			for _, cap := range caps {
				if capStr, ok := cap.(string); ok {
					capStrings = append(capStrings, capStr)
				}
			}
			capabilities.Capabilities[paths[0]] = capStrings
		}

		// Add metadata
		capabilities.Metadata["path_count"] = len(capabilities.Capabilities)
		capabilities.Metadata["has_create_capability"] = false
		capabilities.Metadata["has_read_capability"] = false
		capabilities.Metadata["has_update_capability"] = false
		capabilities.Metadata["has_delete_capability"] = false
		capabilities.Metadata["has_list_capability"] = false
		capabilities.Metadata["has_sudo_capability"] = false

		// Analyze capabilities across all paths
		for _, caps := range capabilities.Capabilities {
			for _, cap := range caps {
				switch cap {
				case "create":
					capabilities.Metadata["has_create_capability"] = true
				case "read":
					capabilities.Metadata["has_read_capability"] = true
				case "update":
					capabilities.Metadata["has_update_capability"] = true
				case "delete":
					capabilities.Metadata["has_delete_capability"] = true
				case "list":
					capabilities.Metadata["has_list_capability"] = true
				case "sudo":
					capabilities.Metadata["has_sudo_capability"] = true
				}
			}
		}
	}

	return capabilities, nil
}

// getCurrentTokenCapabilities gets capabilities for the current token on common paths
func getCurrentTokenCapabilities(ctx context.Context, client *api.Client) (*TokenCapabilities, error) {
	// Use current token
	tokenStr := client.Token()
	if tokenStr == "" {
		return nil, fmt.Errorf("no current token available")
	}

	// Common security-relevant paths to check
	paths := []string{
		"sys/auth",
		"sys/mounts",
		"sys/policies",
		"sys/audit",
		"sys/seal",
		"sys/generate-root",
		"sys/rotate",
	}

	return getTokenCapabilities(ctx, client, tokenStr, paths)
}
