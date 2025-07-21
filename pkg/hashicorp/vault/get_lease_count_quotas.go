package vault

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/api"
)

// LeaseCountQuota represents lease count quota configuration
type LeaseCountQuota struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Path        string `json:"path,omitempty"`
	Namespace   string `json:"namespace,omitempty"`
	Role        string `json:"role,omitempty"`
	MaxLeases   int    `json:"max_leases"`
	Counter     int    `json:"counter"`
	Inheritable bool   `json:"inheritable"`

	// Metadata
	Timestamp string                 `json:"timestamp"`
	Source    string                 `json:"source"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// LeaseCountQuotasInfo represents comprehensive lease count quota information
type LeaseCountQuotasInfo struct {
	Quotas             []LeaseCountQuota `json:"quotas"`
	QuotaCount         int               `json:"quota_count"`
	GlobalQuotasCount  int               `json:"global_quotas_count"`
	NamespaceQuotas    int               `json:"namespace_quotas_count"`
	MountQuotas        int               `json:"mount_quotas_count"`
	TotalLeasesTracked int               `json:"total_leases_tracked"`
	TotalLeaseLimit    int               `json:"total_lease_limit"`

	// Metadata
	Timestamp string                 `json:"timestamp"`
	Source    string                 `json:"source"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// getLeaseCountQuotas retrieves comprehensive lease count quota information from Vault
func getLeaseCountQuotas(ctx context.Context, client *api.Client) (*LeaseCountQuotasInfo, error) {
	// List all lease count quotas
	secret, err := client.Logical().List("sys/quotas/lease-count")
	if err != nil {
		return nil, fmt.Errorf("failed to list lease count quotas: %w", err)
	}

	info := &LeaseCountQuotasInfo{
		Quotas:    make([]LeaseCountQuota, 0),
		Timestamp: getCurrentTimestamp(),
		Source:    "vault_api",
		Metadata:  make(map[string]interface{}),
	}

	if secret != nil && secret.Data != nil {
		if keys, ok := secret.Data["keys"].([]interface{}); ok {
			for _, key := range keys {
				if quotaName, ok := key.(string); ok {
					quota, err := getLeaseCountQuotaDetails(ctx, client, quotaName)
					if err != nil {
						continue // Skip this quota if we can't retrieve details
					}
					info.Quotas = append(info.Quotas, *quota)
				}
			}
		}
	}

	// Calculate statistics
	info.QuotaCount = len(info.Quotas)
	for _, quota := range info.Quotas {
		info.TotalLeasesTracked += quota.Counter
		info.TotalLeaseLimit += quota.MaxLeases

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

	// Calculate utilization percentage
	if info.TotalLeaseLimit > 0 {
		utilization := float64(info.TotalLeasesTracked) / float64(info.TotalLeaseLimit) * 100
		info.Metadata["lease_utilization_percentage"] = utilization
		info.Metadata["lease_utilization_status"] = getUtilizationStatus(utilization)
	}

	return info, nil
}

// getLeaseCountQuotaDetails retrieves detailed information for a specific lease count quota
func getLeaseCountQuotaDetails(ctx context.Context, client *api.Client, quotaName string) (*LeaseCountQuota, error) {
	secret, err := client.Logical().Read(fmt.Sprintf("sys/quotas/lease-count/%s", quotaName))
	if err != nil {
		return nil, fmt.Errorf("failed to read lease count quota %s: %w", quotaName, err)
	}

	quota := &LeaseCountQuota{
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
		if v, ok := secret.Data["max_leases"].(int); ok {
			quota.MaxLeases = v
		}
		if v, ok := secret.Data["counter"].(int); ok {
			quota.Counter = v
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

		// Calculate utilization
		if quota.MaxLeases > 0 {
			utilization := float64(quota.Counter) / float64(quota.MaxLeases) * 100
			quota.Metadata["utilization_percentage"] = utilization
			quota.Metadata["utilization_status"] = getUtilizationStatus(utilization)
			quota.Metadata["leases_remaining"] = quota.MaxLeases - quota.Counter
		}

		// Risk assessment
		quota.Metadata["is_over_limit"] = quota.Counter > quota.MaxLeases
		quota.Metadata["is_near_limit"] = quota.MaxLeases > 0 && float64(quota.Counter)/float64(quota.MaxLeases) > 0.8
	}

	return quota, nil
}

// getUtilizationStatus returns a status string based on utilization percentage
func getUtilizationStatus(utilization float64) string {
	if utilization >= 100 {
		return "over_limit"
	} else if utilization >= 90 {
		return "critical"
	} else if utilization >= 80 {
		return "warning"
	} else if utilization >= 50 {
		return "moderate"
	}
	return "low"
}
