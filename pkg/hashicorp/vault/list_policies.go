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

// ListPolicies creates a tool for listing all ACL policies in Vault
func ListPolicies(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("list_policies",
			mcp.WithDescription("List all ACL policies in Vault"),
			mcp.WithBoolean("include_rules", mcp.DefaultBool(false), mcp.Description("Include policy rules in the response")),
			mcp.WithString("namespace", mcp.Description("The namespace where the policies will be listed.")),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return listPoliciesHandler(ctx, req, logger)
		},
	}
}

func listPoliciesHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling list_policies request")

	// Parse parameters
	includeRules := false
	var namespace string
	if req.Params.Arguments != nil {
		if args, ok := req.Params.Arguments.(map[string]interface{}); ok {
			if val, exists := args["include_rules"]; exists {
				if b, ok := val.(bool); ok {
					includeRules = b
				}
			}
			namespace, _ = args["namespace"].(string)
		}
	}

	logger.WithFields(log.Fields{
		"include_rules": includeRules,
		"namespace":     namespace,
	}).Debug("Listing policies")

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

	// List policies from Vault
	policyNames, err := client.Sys().ListPolicies()
	if err != nil {
		logger.WithError(err).Error("Failed to list policies")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to list policies: %v", err)), nil
	}

	var policies []*Policy
	for _, name := range policyNames {
		policy := &Policy{
			Name: name,
		}

		// Optionally fetch policy rules
		if includeRules {
			rules, err := client.Sys().GetPolicy(name)
			if err != nil {
				logger.WithError(err).WithField("policy", name).Warn("Failed to read policy rules")
				policy.Rules = fmt.Sprintf("Error reading policy: %v", err)
			} else {
				policy.Rules = rules
			}
		}

		policies = append(policies, policy)
	}

	// Marshal to JSON
	jsonData, err := json.Marshal(policies)
	if err != nil {
		logger.WithError(err).Error("Failed to marshal policies to JSON")
		return mcp.NewToolResultError(fmt.Sprintf("Error marshaling JSON: %v", err)), nil
	}

	logger.WithFields(log.Fields{
		"policy_count":  len(policies),
		"include_rules": includeRules,
	}).Debug("Successfully listed policies")

	return mcp.NewToolResultText(string(jsonData)), nil
}
