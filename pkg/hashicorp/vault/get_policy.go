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

// GetPolicy creates a tool for retrieving a specific ACL policy from Vault
func GetPolicy(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("get_policy",
			mcp.WithDescription("Get a specific ACL policy from Vault by name"),
			mcp.WithString("name", mcp.Required(), mcp.Description("The name of the policy to retrieve")),
			mcp.WithString("namespace", mcp.Description("The namespace where the policy is located")),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return getPolicyHandler(ctx, req, logger)
		},
	}
}

func getPolicyHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling get_policy request")

	// Parse parameters
	var policyName, namespace string
	if req.Params.Arguments != nil {
		if args, ok := req.Params.Arguments.(map[string]interface{}); ok {
			policyName, _ = args["name"].(string)
			namespace, _ = args["namespace"].(string)
		}
	}

	if policyName == "" {
		logger.Error("Policy name is required")
		return mcp.NewToolResultError("Policy name is required"), nil
	}

	logger.WithFields(log.Fields{
		"policy_name": policyName,
		"namespace":   namespace,
	}).Debug("Getting policy")

	// Get Vault client from context
	client, err := GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	// Set the namespace on the client
	if namespace != "" {
		client = client.WithNamespace(namespace)
		logger.WithField("namespace", namespace).Debug("Set namespace on Vault client")
	}

	// Get policy from Vault
	rules, err := client.Sys().GetPolicy(policyName)
	if err != nil {
		logger.WithError(err).WithField("policy_name", policyName).Error("Failed to get policy")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get policy '%s': %v", policyName, err)), nil
	}

	// Check if policy exists (GetPolicy returns empty string if policy doesn't exist)
	if rules == "" {
		logger.WithField("policy_name", policyName).Warn("Policy not found")
		return mcp.NewToolResultError(fmt.Sprintf("Policy '%s' not found", policyName)), nil
	}

	policy := &Policy{
		Name:  policyName,
		Rules: rules,
	}

	// Marshal to JSON
	jsonData, err := json.Marshal(policy)
	if err != nil {
		logger.WithError(err).Error("Failed to marshal policy to JSON")
		return mcp.NewToolResultError(fmt.Sprintf("Error marshaling JSON: %v", err)), nil
	}

	logger.WithFields(log.Fields{
		"policy_name": policyName,
		"namespace":   namespace,
	}).Debug("Successfully retrieved policy")

	return mcp.NewToolResultText(string(jsonData)), nil
}
