// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package pki

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault-mcp-server/pkg/client"

	"github.com/hashicorp/vault/api"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
)

// EnablePki creates a tool for creating Vault pki mounts
func EnablePki(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("enable_pki",
			mcp.WithDescription(`Enable the PKI (Public Key Infrastructure) secrets engine in Vault, allowing for the issuance and management of SSL/TLS certificates.
## Setting up the Root CA
  - Create a root PKI mount using this tool, giving it a suitable name that best describes its intended use. Examples could incorporate the domain name in to the name and include 'pki', 'pki_root', or 'pki_ca'.
  - Create a PKI issuer using the 'create_pki_issuer' tool, which will define the CA (Certificate Authority) for the PKI root mount.
  - Create a PKI role using the 'create_pki_role' tool, which will define the policies and constraints for issuing certificates against this root issuer.

## Setting up an Intermediate CA
  - Make sure you have set up the root CA as described above.
  - Create a new intermediate PKI mount using this tool, giving it a suitable name that best describes its intended use. Examples could incorporate the domain name in to the name and include 'pki_int' or 'pki_int_ca'. You will need to specify the 'root_mount' and 'root_issuer' parameters to link it to the root CA.
  - Create a PKI issuer using the 'create_pki_issuer' tool, which will define the CA (Certificate Authority) for the PKI intermediate mount.
  - Create a PKI role using the 'create_pki_role' tool, which will define the policies and constraints for issuing certificates against this intermediate issuer.

## Issuing SSL/TLS Certificates as an Intermediate CA or Root CA
  - Set up the root CA according to the instructions above. If you want to issue certificates as an intermediate CA, make sure you have set up the intermediate CA as well.
  - Create a PKI issuer using the 'create_pki_issuer' tool, which will define the CA (Certificate Authority) for the PKI mount.
  - Create a PKI role using the 'create_pki_role' tool, which will define the policies and constraints for issuing certificates.
  - Issue certificates using the 'issue_pki_certificate' tool, which will allow you to generate certificates based on the defined role.
`),
			mcp.WithString("path",
				mcp.DefaultString("pki"),
				mcp.Description("The path where the pki mount will be created. Defaults to 'pki'."),
			),
			mcp.WithString("description",
				mcp.DefaultString(""),
				mcp.Description("A description for the pki mount."),
			),
			mcp.WithString("max_ttl",
				mcp.DefaultString("87600h"),
				mcp.Description("The maximum time-to-live (TTL) for certificates issued by this PKI mount. Defaults to '87600h' (10 years)."),
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return enablePkiHandler(ctx, req, logger)
		},
	}
}

func enablePkiHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling enable_pki request")

	// Extract parameters
	args, ok := req.Params.Arguments.(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("Missing or invalid arguments format"), nil
	}

	path, ok := args["path"].(string)
	if !ok || path == "" {
		return mcp.NewToolResultError("Missing or invalid 'path' parameter"), nil
	}

	description, _ := args["description"].(string)

	maxTTL, _ := args["max_ttl"].(string)

	logger.WithFields(log.Fields{
		"path":        path,
		"description": description,
	}).Debug("Creating pki mount with parameters")

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
	if _, ok := mounts[path+"/"]; ok {
		// Let the model know that the mount already exists and ift could delete it, need be.
		// We should not delete it automatically, as it could lead to data loss and we should return more options in the future to allow
		// the model to decide what to do with the existing mount (such as tuning).
		return mcp.NewToolResultError(fmt.Sprintf("mount path '%s' already exist, you should use 'delete_mount' if you want to re-create it.", path)), nil
	}

	// Prepare mount input
	mountInput := &api.MountInput{
		Type:        "pki",
		Description: description,
	}

	// Create the mount
	err = vault.Sys().Mount(path, mountInput)
	if err != nil {
		logger.WithError(err).WithFields(log.Fields{
			"path": path,
		}).Error("Failed to create pki mount")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to create pki mount: %v", err)), nil
	}

	mountOptions := api.MountConfigInput{
		MaxLeaseTTL: maxTTL,
	}

	err = vault.Sys().TuneMount(path, mountOptions)

	// Handle error if tuning the mount fails and delete the mount
	if err != nil {
		logger.WithError(err).WithField("path", path).Error("Failed to tune pki mount")
		// Delete the mount
		err = vault.Sys().Unmount(path)
		if err != nil {
			logger.WithError(err).WithField("path", path).Error("Failed to delete pki mount")
			return mcp.NewToolResultError(fmt.Sprintf("Failed to tune pki mount and failed to delete pki mount at path '%s': %v", path, err)), nil
		}
		return mcp.NewToolResultError(fmt.Sprintf("Failed to tune pki mount: %v", err)), nil
	}

	successMsg := fmt.Sprintf("Successfully created pki mount at path '%s'", path)
	if description != "" {
		successMsg += fmt.Sprintf(" with description: %s", description)
	}

	logger.WithFields(log.Fields{
		"path": path,
	}).Info("Successfully created pki mount")

	return mcp.NewToolResultText(successMsg), nil
}
