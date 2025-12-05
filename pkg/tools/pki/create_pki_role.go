// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package pki

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault-mcp-server/pkg/client"
	"github.com/hashicorp/vault-mcp-server/pkg/utils"

	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
)

// CreatePkiRole creates a tool for creating pki roles
func CreatePkiRole(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("create_pki_role",
			mcp.WithDescription("Create a new PKI SSL certificate role in Vault. When creating names, avoid using words like example, demo, or test as they are too generic and may lead to confusion in a production environment."),
			mcp.WithString("mount",
				mcp.DefaultString("pki"),
				mcp.Description("The mount where the pki role will be created. Defaults to 'pki'."),
			),
			mcp.WithString("role_name",
				mcp.Required(),
				mcp.Description("The name of the role. You can use this name to refer to the role when issuing certificates via the issue_pki_certificate tool. This name must be unique within the mount and should be descriptive enough to clearly identify it's use."),
			),
			mcp.WithString("issuer_name",
				mcp.DefaultString("default"),
				mcp.Description("The name of the issuer. This is the name of the issuer that was created with the create_pki_issuer tool. If not specified, it defaults to 'default'. This is useful when you have multiple issuers and want to specify which one to use for this role."),
			),
			mcp.WithBoolean("allow_any_name",
				mcp.DefaultBool(true),
				mcp.Description("This parameter allows the role to issue certificates with any Common Name (CN). If set to true, the role will not restrict the CN of the issued certificates. If set to false, the CN must match one of the allowed domains specified in 'allowed_domains'. Defaults to true."),
			),
			mcp.WithString("allowed_domains",
				mcp.DefaultString(""),
				mcp.Description("This is a comma separated list of allowed domains for the role. If 'allow_any_name' is true, this list will be ignored. If 'allow_glob_domains' is true, you can use wildcards in the domains (e.g., '*.example.com'). If 'allow_ip_sans' is true, you can also specify IP addresses in this list."),
			),
			mcp.WithBoolean("allow_glob_domains",
				mcp.DefaultBool(false),
				mcp.Description("This parameter allows the role to issue certificates with wildcard domains. If set to true, you can use wildcards in the allowed domains (e.g., '*.example.com'). If set to false, only exact domain matches are allowed. Defaults to false."),
			),
			mcp.WithBoolean("allow_ip_sans",
				mcp.DefaultBool(false),
				mcp.Description("This parameter allows the role to issue certificates with IP Subject Alternative Names (SANs). If set to true, you can specify IP addresses in the 'allowed_domains' list. If set to false, only domain names are allowed. Defaults to false."),
			),
			mcp.WithString("max_ttl",
				mcp.DefaultString("30d"),
				mcp.Description("Optional maximum TTL for the role. This is the maximum time that a certificate issued by this role can be valid. Defaults to '30d' (30 days). Other formats are also accepted, such as '87600h' for 10 years."),
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return createPkiRoleHandler(ctx, req, logger)
		},
	}
}

func createPkiRoleHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling create_pki_role request")

	// Extract parameters
	args, ok := req.Params.Arguments.(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("Missing or invalid arguments format"), nil
	}

	mount, err := utils.ExtractMountPath(args)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	roleName, ok := args["role_name"].(string)
	if !ok || roleName == "" {
		return mcp.NewToolResultError("Missing or invalid 'role_name' parameter"), nil
	}

	allowAnyName := args["allow_any_name"].(bool)
	allowGlobDomains := args["allow_glob_domains"].(bool)

	allowIpSans, ok := args["allow_ip_sans"].(bool)
	if !ok {
		allowIpSans = false // Default to false if not provided
	}

	var allowedDomains []string
	if allowedDomainsStr, ok := args["allowed_domains"].(string); ok && allowedDomainsStr != "" {
		allowedDomains = strings.Split(allowedDomainsStr, ",")
		for i := range allowedDomains {
			allowedDomains[i] = strings.TrimSpace(allowedDomains[i])
		}
	}

	maxTTL, _ := args["max_ttl"].(string)

	logger.WithFields(log.Fields{
		"mount":              mount,
		"allow_any_name":     allowAnyName,
		"allow_glob_domains": allowGlobDomains,
		"allow_ip_sans":      allowIpSans,
		"max_ttl":            maxTTL,
		"allowed_domains":    allowedDomains,
	}).Debug("Creating pki role with parameters")

	// Get Vault client from context
	vault, err := client.GetVaultClientFromContext(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("Failed to get Vault client")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get Vault client: %v", err)), nil
	}

	mounts, err := vault.Sys().ListMounts()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to list mounts: %v", err)), nil
	}

	// Check if the mount exists
	if _, ok := mounts[mount+"/"]; !ok {
		return mcp.NewToolResultError(fmt.Sprintf("mount path '%s' does not exist, you should use 'enable_pki' if you want enable pki on this mount.", mount)), nil
	}

	fullPath := fmt.Sprintf("%s/roles/%s", mount, roleName)

	roleData := map[string]interface{}{
		"role_name":          roleName,
		"allow_any_name":     allowAnyName,
		"allow_glob_domains": allowGlobDomains,
		"allow_ip_sans":      allowIpSans,
		"max_ttl":            maxTTL,
		"allowed_domains":    allowedDomains,
	}

	// Write the role data to the specified path
	_, err = vault.Logical().Write(fullPath, roleData)

	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to write to path '%s': %v", fullPath, err)), nil
	}

	successMsg := fmt.Sprintf("Successfully created pki role with name '%s' on mount '%s'.", roleName, mount)

	logger.WithFields(log.Fields{
		"role_name": roleName,
		"max_ttl":   maxTTL,
	}).Info("Successfully created pki role")

	return mcp.NewToolResultText(successMsg), nil
}
