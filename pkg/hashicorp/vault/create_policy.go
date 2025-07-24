// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
)

// CreatePolicy creates a tool for creating or updating ACL policies in Vault
func CreatePolicy(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("create_policy",
			mcp.WithDescription("Create or update an ACL policy in Vault"),
			mcp.WithString("name", mcp.Required(), mcp.Description("The name of the policy to create or update")),
			mcp.WithString("rules", mcp.Required(), mcp.Description("The policy rules in HCL format")),
			mcp.WithString("namespace", mcp.Description("The namespace where the policy will be created.")),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return createPolicyHandler(ctx, req, logger)
		},
	}
}

func createPolicyHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling create_policy request")

	// Extract parameters
	var name, rules, namespace string

	if req.Params.Arguments != nil {
		if args, ok := req.Params.Arguments.(map[string]interface{}); ok {
			if name, ok = args["name"].(string); !ok || name == "" {
				return mcp.NewToolResultError("Missing or invalid 'name' parameter"), nil
			}

			if rules, ok = args["rules"].(string); !ok || rules == "" {
				return mcp.NewToolResultError("Missing or invalid 'rules' parameter"), nil
			}

			namespace, _ = args["namespace"].(string)
		} else {
			return mcp.NewToolResultError("Invalid arguments format"), nil
		}
	} else {
		return mcp.NewToolResultError("Missing arguments"), nil
	}

	logger.WithFields(log.Fields{
		"policy_name": name,
		"namespace":   namespace,
	}).Debug("Creating/updating policy")

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

	// Create/update the policy
	err = client.Sys().PutPolicy(name, rules)
	if err != nil {
		logger.WithError(err).WithField("policy_name", name).Error("Failed to create/update policy")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to create/update policy '%s': %v", name, err)), nil
	}

	successMsg := fmt.Sprintf("Successfully created/updated policy '%s'", name)
	logger.WithField("policy_name", name).Info("Policy created/updated successfully")

	return mcp.NewToolResultText(successMsg), nil
}
