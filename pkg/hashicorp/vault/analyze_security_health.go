// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
)

// SecurityHealthScope defines the scope of security health analysis
type SecurityHealthScope struct {
	IncludeHealth      bool     `json:"include_health"`
	IncludeAudit       bool     `json:"include_audit"`
	IncludePolicies    bool     `json:"include_policies"`
	IncludeAuthMethods bool     `json:"include_auth_methods"`
	IncludeMounts      bool     `json:"include_mounts"`
	IncludeUIConfig    bool     `json:"include_ui_config"`
	CustomChecks       []string `json:"custom_checks,omitempty"`
}

// SecurityHealthData aggregates all security-related data from Vault
type SecurityHealthData struct {
	Health      *HealthStatus           `json:"health,omitempty"`
	SealStatus  *SealStatus             `json:"seal_status,omitempty"`
	Audit       []*AuditDevice          `json:"audit_devices,omitempty"`
	AuthMethods []*AuthMethod           `json:"auth_methods,omitempty"`
	Policies    []*Policy               `json:"policies,omitempty"`
	Mounts      []*Mount                `json:"mounts,omitempty"`
	UIHeaders   map[string]string       `json:"ui_headers,omitempty"`
	Metadata    *SecurityHealthMetadata `json:"metadata"`
}

// SecurityHealthMetadata contains analysis metadata
type SecurityHealthMetadata struct {
	Timestamp    string   `json:"timestamp"`
	VaultVersion string   `json:"vault_version"`
	Scope        []string `json:"scope"`
	Errors       []string `json:"errors,omitempty"`
	Warnings     []string `json:"warnings,omitempty"`
}

// AnalyzeSecurityHealth creates a tool for comprehensive security health analysis
func AnalyzeSecurityHealth(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("analyze_security_health",
			mcp.WithDescription("Comprehensive security health analysis of Vault cluster"),
			mcp.WithBoolean("parallel", mcp.DefaultBool(true), mcp.Description("Execute checks in parallel")),
			mcp.WithBoolean("fail_fast", mcp.DefaultBool(false), mcp.Description("Stop on first critical error")),
			mcp.WithBoolean("include_health", mcp.DefaultBool(true), mcp.Description("Include health status check")),
			mcp.WithBoolean("include_audit", mcp.DefaultBool(true), mcp.Description("Include audit devices check")),
			mcp.WithBoolean("include_policies", mcp.DefaultBool(true), mcp.Description("Include policies check")),
			mcp.WithBoolean("include_auth_methods", mcp.DefaultBool(true), mcp.Description("Include auth methods check")),
			mcp.WithBoolean("include_mounts", mcp.DefaultBool(true), mcp.Description("Include mounts check")),
			mcp.WithBoolean("include_ui_config", mcp.DefaultBool(true), mcp.Description("Include UI configuration check")),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return analyzeSecurityHealthHandler(ctx, req, logger)
		},
	}
}

func analyzeSecurityHealthHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling analyze_security_health request")

	// Parse parameters
	scope, parallel, failFast, err := parseAnalysisParameters(req)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Invalid parameters: %v", err)), nil
	}

	// Get Vault client from context
	client, err := GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	// Initialize result data structure
	data := &SecurityHealthData{
		Metadata: &SecurityHealthMetadata{
			Timestamp: getCurrentTimestamp(),
			Scope:     getScopeList(scope),
		},
	}

	// Execute data collection based on scope
	if parallel {
		err = collectDataParallel(ctx, client, scope, data, logger)
	} else {
		err = collectDataSequential(ctx, client, scope, data, failFast, logger)
	}

	if err != nil && failFast {
		return mcp.NewToolResultError(fmt.Sprintf("Security health analysis failed: %v", err)), nil
	}

	// Marshal the aggregated data
	jsonData, err := json.Marshal(data)
	if err != nil {
		logger.WithError(err).Error("Failed to marshal security health data")
		return mcp.NewToolResultError(fmt.Sprintf("Error marshaling JSON: %v", err)), nil
	}

	logger.WithFields(log.Fields{
		"scope_count": len(data.Metadata.Scope),
		"has_errors":  len(data.Metadata.Errors) > 0,
	}).Debug("Successfully completed security health analysis")

	return mcp.NewToolResultText(string(jsonData)), nil
}

func collectDataParallel(ctx context.Context, client *api.Client, scope *SecurityHealthScope, data *SecurityHealthData, logger *log.Logger) error {
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Collect health status
	if scope.IncludeHealth {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if health, err := collectHealthStatus(ctx, client, logger); err != nil {
				mu.Lock()
				data.Metadata.Errors = append(data.Metadata.Errors, fmt.Sprintf("Health check failed: %v", err))
				mu.Unlock()
			} else {
				mu.Lock()
				data.Health = health
				mu.Unlock()
			}
		}()
	}

	// Collect audit devices
	if scope.IncludeAudit {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if audit, err := collectAuditDevices(ctx, client, logger); err != nil {
				mu.Lock()
				data.Metadata.Errors = append(data.Metadata.Errors, fmt.Sprintf("Audit collection failed: %v", err))
				mu.Unlock()
			} else {
				mu.Lock()
				data.Audit = audit
				mu.Unlock()
			}
		}()
	}

	// Collect auth methods
	if scope.IncludeAuthMethods {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if authMethods, err := collectAuthMethods(ctx, client, logger); err != nil {
				mu.Lock()
				data.Metadata.Errors = append(data.Metadata.Errors, fmt.Sprintf("Auth methods collection failed: %v", err))
				mu.Unlock()
			} else {
				mu.Lock()
				data.AuthMethods = authMethods
				mu.Unlock()
			}
		}()
	}

	// Collect policies
	if scope.IncludePolicies {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if policies, err := collectPolicies(ctx, client, logger); err != nil {
				mu.Lock()
				data.Metadata.Errors = append(data.Metadata.Errors, fmt.Sprintf("Policies collection failed: %v", err))
				mu.Unlock()
			} else {
				mu.Lock()
				data.Policies = policies
				mu.Unlock()
			}
		}()
	}

	// Collect mounts
	if scope.IncludeMounts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if mounts, err := collectMounts(ctx, client, logger); err != nil {
				mu.Lock()
				data.Metadata.Errors = append(data.Metadata.Errors, fmt.Sprintf("Mounts collection failed: %v", err))
				mu.Unlock()
			} else {
				mu.Lock()
				data.Mounts = mounts
				mu.Unlock()
			}
		}()
	}

	// Collect UI headers
	if scope.IncludeUIConfig {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if uiHeaders, err := collectUIHeaders(ctx, client, logger); err != nil {
				mu.Lock()
				data.Metadata.Warnings = append(data.Metadata.Warnings, fmt.Sprintf("UI headers collection failed: %v", err))
				mu.Unlock()
			} else {
				mu.Lock()
				data.UIHeaders = uiHeaders
				mu.Unlock()
			}
		}()
	}

	wg.Wait()
	return nil
}

func collectDataSequential(ctx context.Context, client *api.Client, scope *SecurityHealthScope, data *SecurityHealthData, failFast bool, logger *log.Logger) error {
	// Sequential collection with proper error handling
	if scope.IncludeHealth {
		if health, err := collectHealthStatus(ctx, client, logger); err != nil {
			data.Metadata.Errors = append(data.Metadata.Errors, fmt.Sprintf("Health check failed: %v", err))
			if failFast {
				return err
			}
		} else {
			data.Health = health
		}
	}

	if scope.IncludeAudit {
		if audit, err := collectAuditDevices(ctx, client, logger); err != nil {
			data.Metadata.Errors = append(data.Metadata.Errors, fmt.Sprintf("Audit collection failed: %v", err))
			if failFast {
				return err
			}
		} else {
			data.Audit = audit
		}
	}

	if scope.IncludeAuthMethods {
		if authMethods, err := collectAuthMethods(ctx, client, logger); err != nil {
			data.Metadata.Errors = append(data.Metadata.Errors, fmt.Sprintf("Auth methods collection failed: %v", err))
			if failFast {
				return err
			}
		} else {
			data.AuthMethods = authMethods
		}
	}

	if scope.IncludePolicies {
		if policies, err := collectPolicies(ctx, client, logger); err != nil {
			data.Metadata.Errors = append(data.Metadata.Errors, fmt.Sprintf("Policies collection failed: %v", err))
			if failFast {
				return err
			}
		} else {
			data.Policies = policies
		}
	}

	if scope.IncludeMounts {
		if mounts, err := collectMounts(ctx, client, logger); err != nil {
			data.Metadata.Errors = append(data.Metadata.Errors, fmt.Sprintf("Mounts collection failed: %v", err))
			if failFast {
				return err
			}
		} else {
			data.Mounts = mounts
		}
	}

	if scope.IncludeUIConfig {
		if uiHeaders, err := collectUIHeaders(ctx, client, logger); err != nil {
			data.Metadata.Warnings = append(data.Metadata.Warnings, fmt.Sprintf("UI headers collection failed: %v", err))
			// UI headers failure is not critical, so don't fail fast
		} else {
			data.UIHeaders = uiHeaders
		}
	}

	return nil
}

// Helper functions for data collection
func collectHealthStatus(ctx context.Context, client *api.Client, logger *log.Logger) (*HealthStatus, error) {
	health, err := client.Sys().Health()
	if err != nil {
		return nil, err
	}

	return &HealthStatus{
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
	}, nil
}

func collectAuditDevices(ctx context.Context, client *api.Client, logger *log.Logger) ([]*AuditDevice, error) {
	audits, err := client.Sys().ListAudit()
	if err != nil {
		return nil, err
	}

	var devices []*AuditDevice
	for path, audit := range audits {
		devices = append(devices, &AuditDevice{
			Type:        audit.Type,
			Description: audit.Description,
			Options:     audit.Options,
			Path:        path,
		})
	}

	return devices, nil
}

func collectAuthMethods(ctx context.Context, client *api.Client, logger *log.Logger) ([]*AuthMethod, error) {
	authMethods, err := client.Sys().ListAuth()
	if err != nil {
		return nil, err
	}

	var methods []*AuthMethod
	for k, v := range authMethods {
		method := &AuthMethod{
			Name:                  k,
			Type:                  v.Type,
			Description:           v.Description,
			Accessor:              v.Accessor,
			Local:                 v.Local,
			SealWrap:              v.SealWrap,
			ExternalEntropyAccess: v.ExternalEntropyAccess,
			Options:               v.Options,
			UUID:                  v.UUID,
			PluginVersion:         v.PluginVersion,
			RunningSha256:         v.RunningSha256,
			DeprecationStatus:     v.DeprecationStatus,
		}

		method.Config = &AuthMethodConfig{
			DefaultLeaseTTL: v.Config.DefaultLeaseTTL,
			MaxLeaseTTL:     v.Config.MaxLeaseTTL,
			ForceNoCache:    v.Config.ForceNoCache,
			TokenType:       v.Config.TokenType,
		}

		// Collect root credentials rotation information
		method.RootRotationConfig = collectRootRotationInfo(ctx, client, k, v.Type, logger)

		methods = append(methods, method)
	}

	return methods, nil
}

// collectRootRotationInfo collects root credentials rotation information for an auth method
func collectRootRotationInfo(ctx context.Context, client *api.Client, authPath, authType string, logger *log.Logger) *RootCredentialsRotation {
	// Initialize with defaults
	rotation := &RootCredentialsRotation{
		Supported:              false,
		Enabled:                false,
		ManualRotationRequired: false,
		DaysSinceLastRotation:  -1,
	}

	// Check if this auth method type supports root credential rotation
	supportedTypes := map[string]bool{
		"aws":        true,
		"azure":      true,
		"gcp":        true,
		"ldap":       true,
		"database":   true,
		"ad":         true,
		"kubernetes": false, // K8s doesn't typically have rotatable root creds
		"github":     false, // GitHub tokens are managed externally
		"userpass":   false, // No root credentials to rotate
		"token":      false, // Token auth doesn't have root credentials
	}

	if supported, exists := supportedTypes[authType]; exists && supported {
		rotation.Supported = true
	} else {
		// For unknown types, assume they might support it
		rotation.Supported = true
	}

	if !rotation.Supported {
		return rotation
	}

	// Try to get root credentials configuration
	cleanPath := strings.TrimSuffix(authPath, "/")
	configPath := fmt.Sprintf("auth/%s/config/rotate-root", cleanPath)

	logger.WithFields(log.Fields{
		"auth_path":   cleanPath,
		"auth_type":   authType,
		"config_path": configPath,
	}).Debug("Checking root rotation configuration")

	// Attempt to read the rotate-root configuration
	secret, err := client.Logical().Read(configPath)
	if err != nil {
		logger.WithError(err).WithField("path", configPath).Debug("Failed to read root rotation config (may not be configured)")
		return rotation
	}

	if secret == nil || secret.Data == nil {
		logger.WithField("path", configPath).Debug("No root rotation configuration found")
		return rotation
	}

	// Parse rotation configuration
	if val, exists := secret.Data["auto_rotate"]; exists {
		if enabled, ok := val.(bool); ok {
			rotation.Enabled = enabled
		}
	}

	if val, exists := secret.Data["rotate_period"]; exists {
		if period, ok := val.(int); ok {
			rotation.RotationPeriod = period
		} else if periodStr, ok := val.(string); ok {
			// Handle duration strings like "24h", "30d", etc.
			if duration, err := time.ParseDuration(periodStr); err == nil {
				rotation.RotationPeriod = int(duration.Seconds())
			}
		}
	}

	// Try to get last rotation information
	statusPath := fmt.Sprintf("auth/%s/config/rotate-root/status", cleanPath)
	statusSecret, err := client.Logical().Read(statusPath)
	if err == nil && statusSecret != nil && statusSecret.Data != nil {
		if val, exists := statusSecret.Data["last_rotation_time"]; exists {
			if lastRotation, ok := val.(string); ok {
				rotation.LastRotationTime = lastRotation

				// Calculate days since last rotation
				if lastTime, err := time.Parse(time.RFC3339, lastRotation); err == nil {
					daysSince := int(time.Since(lastTime).Hours() / 24)
					rotation.DaysSinceLastRotation = daysSince
				}
			}
		}

		if val, exists := statusSecret.Data["status"]; exists {
			if status, ok := val.(string); ok {
				rotation.RotationStatus = status
			}
		}
	}

	// Calculate next rotation time if auto-rotation is enabled
	if rotation.Enabled && rotation.RotationPeriod > 0 && rotation.LastRotationTime != "" {
		if lastTime, err := time.Parse(time.RFC3339, rotation.LastRotationTime); err == nil {
			nextTime := lastTime.Add(time.Duration(rotation.RotationPeriod) * time.Second)
			rotation.NextRotationTime = nextTime.Format(time.RFC3339)
		}
	}

	// Determine if manual rotation is required (arbitrary threshold of 90 days)
	if rotation.DaysSinceLastRotation > 90 {
		rotation.ManualRotationRequired = true
	}

	return rotation
}

func collectPolicies(ctx context.Context, client *api.Client, logger *log.Logger) ([]*Policy, error) {
	policyNames, err := client.Sys().ListPolicies()
	if err != nil {
		return nil, err
	}

	var policies []*Policy
	for _, name := range policyNames {
		policy, err := client.Sys().GetPolicy(name)
		if err != nil {
			logger.WithError(err).WithField("policy", name).Warn("Failed to read policy")
			continue
		}

		policies = append(policies, &Policy{
			Name:  name,
			Rules: policy,
		})
	}

	return policies, nil
}

func collectMounts(ctx context.Context, client *api.Client, logger *log.Logger) ([]*Mount, error) {
	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return nil, err
	}

	var mountList []*Mount
	for k, v := range mounts {
		mount := &Mount{
			Name:            k,
			Type:            v.Type,
			Description:     v.Description,
			DefaultLeaseTTL: v.Config.DefaultLeaseTTL,
			MaxLeaseTTL:     v.Config.MaxLeaseTTL,
		}
		mountList = append(mountList, mount)
	}

	return mountList, nil
}

func collectUIHeaders(ctx context.Context, client *api.Client, logger *log.Logger) (map[string]string, error) {
	// This is a placeholder - the actual API endpoint may vary
	// For now, return empty map to avoid blocking the analysis
	logger.Debug("UI headers collection not implemented yet")
	return make(map[string]string), nil
}

// Additional helper functions...
func parseAnalysisParameters(req mcp.CallToolRequest) (*SecurityHealthScope, bool, bool, error) {
	// Default scope
	scope := &SecurityHealthScope{
		IncludeHealth:      true,
		IncludeAudit:       true,
		IncludePolicies:    true,
		IncludeAuthMethods: true,
		IncludeMounts:      true,
		IncludeUIConfig:    true,
	}

	parallel := true
	failFast := false

	if req.Params.Arguments != nil {
		if args, ok := req.Params.Arguments.(map[string]interface{}); ok {
			// Parse execution parameters
			if val, exists := args["parallel"]; exists {
				if b, ok := val.(bool); ok {
					parallel = b
				}
			}

			if val, exists := args["fail_fast"]; exists {
				if b, ok := val.(bool); ok {
					failFast = b
				}
			}

			// Parse scope parameters
			if val, exists := args["include_health"]; exists {
				if b, ok := val.(bool); ok {
					scope.IncludeHealth = b
				}
			}

			if val, exists := args["include_audit"]; exists {
				if b, ok := val.(bool); ok {
					scope.IncludeAudit = b
				}
			}

			if val, exists := args["include_policies"]; exists {
				if b, ok := val.(bool); ok {
					scope.IncludePolicies = b
				}
			}

			if val, exists := args["include_auth_methods"]; exists {
				if b, ok := val.(bool); ok {
					scope.IncludeAuthMethods = b
				}
			}

			if val, exists := args["include_mounts"]; exists {
				if b, ok := val.(bool); ok {
					scope.IncludeMounts = b
				}
			}

			if val, exists := args["include_ui_config"]; exists {
				if b, ok := val.(bool); ok {
					scope.IncludeUIConfig = b
				}
			}
		}
	}

	return scope, parallel, failFast, nil
}

func getCurrentTimestamp() string {
	return time.Now().UTC().Format(time.RFC3339)
}

func getScopeList(scope *SecurityHealthScope) []string {
	var scopeList []string
	if scope.IncludeHealth {
		scopeList = append(scopeList, "health")
	}
	if scope.IncludeAudit {
		scopeList = append(scopeList, "audit")
	}
	if scope.IncludePolicies {
		scopeList = append(scopeList, "policies")
	}
	if scope.IncludeAuthMethods {
		scopeList = append(scopeList, "auth_methods")
	}
	if scope.IncludeMounts {
		scopeList = append(scopeList, "mounts")
	}
	if scope.IncludeUIConfig {
		scopeList = append(scopeList, "ui_config")
	}
	return scopeList
}

// Placeholder types that would be defined in their respective tool files
type HealthStatus struct {
	Initialized                bool   `json:"initialized"`
	Sealed                     bool   `json:"sealed"`
	Standby                    bool   `json:"standby"`
	PerformanceStandby         bool   `json:"performance_standby"`
	ReplicationPerformanceMode string `json:"replication_performance_mode"`
	ReplicationDRMode          string `json:"replication_dr_mode"`
	ServerTimeUTC              int64  `json:"server_time_utc"`
	Version                    string `json:"version"`
	ClusterName                string `json:"cluster_name"`
	ClusterID                  string `json:"cluster_id"`
}

type SealStatus struct {
	Type         string `json:"type"`
	Initialized  bool   `json:"initialized"`
	Sealed       bool   `json:"sealed"`
	T            int    `json:"t"`
	N            int    `json:"n"`
	Progress     int    `json:"progress"`
	Nonce        string `json:"nonce"`
	Version      string `json:"version"`
	BuildDate    string `json:"build_date"`
	Migration    bool   `json:"migration"`
	ClusterName  string `json:"cluster_name"`
	ClusterID    string `json:"cluster_id"`
	RecoverySeal bool   `json:"recovery_seal"`
	StorageType  string `json:"storage_type"`
}

type AuditDevice struct {
	Type        string            `json:"type"`
	Description string            `json:"description"`
	Options     map[string]string `json:"options"`
	Path        string            `json:"path"`
}

type Policy struct {
	Name  string `json:"name"`
	Rules string `json:"rules"`
}
