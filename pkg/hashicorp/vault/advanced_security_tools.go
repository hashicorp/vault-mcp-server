package vault

import (
	"context"
	"encoding/json"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
)

// GetRootGenerationStatus creates a tool for monitoring root token generation status
func GetRootGenerationStatus(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("get_root_generation_status",
			mcp.WithDescription("Monitor root token generation attempts and status for security compliance"),
		),
		Handler: func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			client, err := GetVaultClientFromContext(ctx, logger)
			if err != nil {
				return mcp.NewToolResultError("failed to create client: " + err.Error()), nil
			}

			status, err := getRootGenerationStatus(client, ctx)
			if err != nil {
				return mcp.NewToolResultError("failed to get root generation status: " + err.Error()), nil
			}

			result, _ := json.Marshal(status)
			return mcp.NewToolResultText(string(result)), nil
		},
	}
}

// GetRateLimitQuotas creates a tool for analyzing rate limit quotas
func GetRateLimitQuotas(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("get_rate_limit_quotas",
			mcp.WithDescription("Analyze rate limit quotas configuration and usage for API protection"),
		),
		Handler: func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			client, err := GetVaultClientFromContext(ctx, logger)
			if err != nil {
				return mcp.NewToolResultError("failed to create client: " + err.Error()), nil
			}

			quotas, err := getRateLimitQuotas(ctx, client)
			if err != nil {
				return mcp.NewToolResultError("failed to get rate limit quotas: " + err.Error()), nil
			}

			result, _ := json.Marshal(quotas)
			return mcp.NewToolResultText(string(result)), nil
		},
	}
}

// GetLeaseCountQuotas creates a tool for analyzing lease count quotas
func GetLeaseCountQuotas(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("get_lease_count_quotas",
			mcp.WithDescription("Analyze lease count quotas configuration and utilization for resource management"),
		),
		Handler: func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			client, err := GetVaultClientFromContext(ctx, logger)
			if err != nil {
				return mcp.NewToolResultError("failed to create client: " + err.Error()), nil
			}

			quotas, err := getLeaseCountQuotas(ctx, client)
			if err != nil {
				return mcp.NewToolResultError("failed to get lease count quotas: " + err.Error()), nil
			}

			result, _ := json.Marshal(quotas)
			return mcp.NewToolResultText(string(result)), nil
		},
	}
}

// GetReplicationStatus creates a tool for comprehensive replication analysis
func GetReplicationStatus(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("get_replication_status",
			mcp.WithDescription("Comprehensive replication status analysis including DR and performance replication health"),
		),
		Handler: func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			client, err := GetVaultClientFromContext(ctx, logger)
			if err != nil {
				return mcp.NewToolResultError("failed to create client: " + err.Error()), nil
			}

			status, err := getReplicationStatus(ctx, client)
			if err != nil {
				return mcp.NewToolResultError("failed to get replication status: " + err.Error()), nil
			}

			result, _ := json.Marshal(status)
			return mcp.NewToolResultText(string(result)), nil
		},
	}
}

// GetSanitizedConfig creates a tool for Vault configuration analysis
func GetSanitizedConfig(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("get_sanitized_config",
			mcp.WithDescription("Analyze Vault configuration for security compliance and best practices"),
		),
		Handler: func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			client, err := GetVaultClientFromContext(ctx, logger)
			if err != nil {
				return mcp.NewToolResultError("failed to create client: " + err.Error()), nil
			}

			config, err := getSanitizedConfig(ctx, client)
			if err != nil {
				return mcp.NewToolResultError("failed to get sanitized config: " + err.Error()), nil
			}

			result, _ := json.Marshal(config)
			return mcp.NewToolResultText(string(result)), nil
		},
	}
}

// GetCORSConfig creates a tool for CORS configuration analysis
func GetCORSConfig(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("get_cors_config",
			mcp.WithDescription("Analyze CORS configuration for web security compliance"),
		),
		Handler: func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			client, err := GetVaultClientFromContext(ctx, logger)
			if err != nil {
				return mcp.NewToolResultError("failed to create client: " + err.Error()), nil
			}

			config, err := getCORSConfig(ctx, client)
			if err != nil {
				return mcp.NewToolResultError("failed to get CORS config: " + err.Error()), nil
			}

			result, _ := json.Marshal(config)
			return mcp.NewToolResultText(string(result)), nil
		},
	}
}

// GetLeaseCounts creates a tool for lease management analysis
func GetLeaseCounts(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("get_lease_counts",
			mcp.WithDescription("Analyze lease counts and management for resource monitoring"),
		),
		Handler: func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			client, err := GetVaultClientFromContext(ctx, logger)
			if err != nil {
				return mcp.NewToolResultError("failed to create client: " + err.Error()), nil
			}

			counts, err := getLeaseCounts(ctx, client)
			if err != nil {
				return mcp.NewToolResultError("failed to get lease counts: " + err.Error()), nil
			}

			result, _ := json.Marshal(counts)
			return mcp.NewToolResultText(string(result)), nil
		},
	}
}

// GetCurrentTokenCapabilities creates a tool for token capability analysis
func GetCurrentTokenCapabilities(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("get_current_token_capabilities",
			mcp.WithDescription("Analyze current token capabilities across security-critical paths"),
		),
		Handler: func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			client, err := GetVaultClientFromContext(ctx, logger)
			if err != nil {
				return mcp.NewToolResultError("failed to create client: " + err.Error()), nil
			}

			capabilities, err := getCurrentTokenCapabilities(ctx, client)
			if err != nil {
				return mcp.NewToolResultError("failed to get token capabilities: " + err.Error()), nil
			}

			result, _ := json.Marshal(capabilities)
			return mcp.NewToolResultText(string(result)), nil
		},
	}
}
