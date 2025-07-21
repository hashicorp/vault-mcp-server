package vault

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/api"
)

// RateLimitQuota represents rate limit quota configuration
type RateLimitQuota struct {
	Name          string  `json:"name"`
	Type          string  `json:"type"`
	Path          string  `json:"path,omitempty"`
	Namespace     string  `json:"namespace,omitempty"`
	Role          string  `json:"role,omitempty"`
	Rate          float64 `json:"rate"`
	Interval      string  `json:"interval,omitempty"`
	BlockInterval string  `json:"block_interval,omitempty"`
	GroupBy       string  `json:"group_by,omitempty"`
	Inheritable   bool    `json:"inheritable"`

	// Metadata
	Timestamp string                 `json:"timestamp"`
	Source    string                 `json:"source"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// RateLimitQuotasInfo represents comprehensive rate limit quota information
type RateLimitQuotasInfo struct {
	Quotas            []RateLimitQuota       `json:"quotas"`
	QuotaCount        int                    `json:"quota_count"`
	GlobalQuotasCount int                    `json:"global_quotas_count"`
	NamespaceQuotas   int                    `json:"namespace_quotas_count"`
	MountQuotas       int                    `json:"mount_quotas_count"`
	Configuration     map[string]interface{} `json:"configuration,omitempty"`

	// Metadata
	Timestamp string                 `json:"timestamp"`
	Source    string                 `json:"source"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// getRateLimitQuotas retrieves comprehensive rate limit quota information from Vault
func getRateLimitQuotas(ctx context.Context, client *api.Client) (*RateLimitQuotasInfo, error) {
	// List all rate limit quotas
	secret, err := client.Logical().List("sys/quotas/rate-limit")
	if err != nil {
		return nil, fmt.Errorf("failed to list rate limit quotas: %w", err)
	}

	info := &RateLimitQuotasInfo{
		Quotas:    make([]RateLimitQuota, 0),
		Timestamp: getCurrentTimestamp(),
		Source:    "vault_api",
		Metadata:  make(map[string]interface{}),
	}

	if secret != nil && secret.Data != nil {
		if keys, ok := secret.Data["keys"].([]interface{}); ok {
			for _, key := range keys {
				if quotaName, ok := key.(string); ok {
					quota, err := getRateLimitQuotaDetails(ctx, client, quotaName)
					if err != nil {
						continue // Skip this quota if we can't retrieve details
					}
					info.Quotas = append(info.Quotas, *quota)
				}
			}
		}
	}

	// Get quota configuration
	configSecret, err := client.Logical().Read("sys/quotas/config")
	if err == nil && configSecret != nil && configSecret.Data != nil {
		info.Configuration = configSecret.Data
	}

	// Calculate statistics
	info.QuotaCount = len(info.Quotas)
	for _, quota := range info.Quotas {
		if quota.Path == "" {
			info.GlobalQuotasCount++
		} else if quota.Path != "" && quota.Role == "" {
			// Check if it's a namespace or mount quota
			if len(quota.Path) > 0 && quota.Path[len(quota.Path)-1] == '/' {
				info.NamespaceQuotas++
			} else {
				info.MountQuotas++
			}
		}
	}

	// Add metadata
	info.Metadata["has_quotas"] = info.QuotaCount > 0
	info.Metadata["has_global_quotas"] = info.GlobalQuotasCount > 0
	info.Metadata["quota_coverage"] = map[string]int{
		"global":    info.GlobalQuotasCount,
		"namespace": info.NamespaceQuotas,
		"mount":     info.MountQuotas,
	}

	return info, nil
}

// getRateLimitQuotaDetails retrieves detailed information for a specific rate limit quota
func getRateLimitQuotaDetails(ctx context.Context, client *api.Client, quotaName string) (*RateLimitQuota, error) {
	secret, err := client.Logical().Read(fmt.Sprintf("sys/quotas/rate-limit/%s", quotaName))
	if err != nil {
		return nil, fmt.Errorf("failed to read rate limit quota %s: %w", quotaName, err)
	}

	quota := &RateLimitQuota{
		Name:      quotaName,
		Timestamp: getCurrentTimestamp(),
		Source:    "vault_api",
		Metadata:  make(map[string]interface{}),
	}

	if secret != nil && secret.Data != nil {
		if v, ok := secret.Data["type"].(string); ok {
			quota.Type = v
		}
		if v, ok := secret.Data["path"].(string); ok {
			quota.Path = v
		}
		if v, ok := secret.Data["namespace"].(string); ok {
			quota.Namespace = v
		}
		if v, ok := secret.Data["role"].(string); ok {
			quota.Role = v
		}
		if v, ok := secret.Data["rate"].(float64); ok {
			quota.Rate = v
		}
		if v, ok := secret.Data["interval"].(string); ok {
			quota.Interval = v
		}
		if v, ok := secret.Data["block_interval"].(string); ok {
			quota.BlockInterval = v
		}
		if v, ok := secret.Data["group_by"].(string); ok {
			quota.GroupBy = v
		}
		if v, ok := secret.Data["inheritable"].(bool); ok {
			quota.Inheritable = v
		}

		// Determine quota scope
		scope := "specific"
		if quota.Path == "" {
			scope = "global"
		} else if quota.Path != "" && quota.Role == "" {
			if len(quota.Path) > 0 && quota.Path[len(quota.Path)-1] == '/' {
				scope = "namespace"
			} else {
				scope = "mount"
			}
		}
		quota.Metadata["scope"] = scope
		quota.Metadata["is_restrictive"] = quota.Rate < 1000 // Configurable threshold
	}

	return quota, nil
}
