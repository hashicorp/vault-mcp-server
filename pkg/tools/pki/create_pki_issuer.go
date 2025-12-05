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

// CreatePkiIssuer creates a tool for creating pki issuers
func CreatePkiIssuer(logger *log.Logger) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("create_pki_issuer",
			mcp.WithDescription("Create a new PKI  SSL certificate issuer in Vault. When creating names, avoid using words like example, demo, or test as they are too generic and may lead to confusion in a production environment."),
			mcp.WithString("mount",
				mcp.DefaultString("pki"),
				mcp.Description("The mount where the pki issuer will be created. Defaults to 'pki'."),
			),
			mcp.WithString("type",
				mcp.Required(),
				mcp.Enum("internal"),
				mcp.Description("The type of issuer. Currently only 'internal' is supported for PKI issuers."),
			),
			mcp.WithString("common_name",
				mcp.Required(),
				mcp.Description("Common Name (CN) for the PKI issuer. This is typically the name of the organization or entity that the certificates will be issued for. Examples would be example.com or My Company."),
			),
			mcp.WithString("issuer_name",
				mcp.Required(),
				mcp.Description("Unique name of the issuer which will be used to identify the issuer in Vault. This is not the common name of the certificate itself but, could be derived from the common name if it makes sense."),
			),
			mcp.WithString("ttl",
				mcp.DefaultString("30d"),
				mcp.Description("Optional default ttl for the issuer. Defaults to '30d' (30 days). Other formats are also accepted, such as '87600h' for 10 years."),
			),
			mcp.WithString("root_mount",
				mcp.DefaultString(""),
				mcp.Description("Optional root certificate mount, if you are creating an intermediate certificate issuer."),
			),
			mcp.WithString("root_issuer",
				mcp.DefaultString(""),
				mcp.Description("Optional root issuer name. This issuer must be present in the Vault PKI mount specified by 'root_mount'."),
			),
		),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return createPkiIssuerHandler(ctx, req, logger)
		},
	}
}

func createPkiIssuerHandler(ctx context.Context, req mcp.CallToolRequest, logger *log.Logger) (*mcp.CallToolResult, error) {
	logger.Debug("Handling create_pki_issuer request")

	// Extract parameters
	args, ok := req.Params.Arguments.(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("Missing or invalid arguments format"), nil
	}

	mount, err := utils.ExtractMountPath(args)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	issuerType, ok := args["type"].(string)
	if !ok || issuerType != "internal" {
		return mcp.NewToolResultError("Missing or invalid 'type' parameter"), nil
	}

	commonName, ok := args["common_name"].(string)
	if !ok || commonName == "" {
		return mcp.NewToolResultError("Missing or invalid 'common_name' parameter"), nil
	}

	issuerName, ok := args["issuer_name"].(string)
	if !ok || issuerName == "" {
		return mcp.NewToolResultError("Missing or invalid 'issuer_name' parameter"), nil
	}

	ttl, _ := args["ttl"].(string)

	rootMount, _ := args["root_mount"].(string)
	rootIssuer, _ := args["root_issuer"].(string)

	logger.WithFields(log.Fields{
		"mount":       mount,
		"type":        issuerType,
		"common_name": commonName,
		"issuer_name": issuerName,
		"ttl":         ttl,
		"root_mount":  rootMount,
		"root_issuer": rootIssuer,
	}).Debug("Creating certificate issuer with parameters")

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

	fullPath := fmt.Sprintf("%s/root/generate/%s", mount, issuerType)

	// If we have been passed a root issuer, we need to create an intermediate issuer
	if rootMount != "" && rootIssuer != "" {

		// Check if the root mount exists
		if _, ok := mounts[rootMount+"/"]; !ok {
			return mcp.NewToolResultError(fmt.Sprintf("root mount path '%s' does not exist, you should use 'enable_pki' if you want enable pki on this mount.", mount)), nil
		}

		fullPath = fmt.Sprintf("%s/intermediate/generate/%s", mount, issuerType)
	}

	issuerData := map[string]interface{}{
		"common_name": commonName,
		"issuer_name": issuerName,
		"ttl":         ttl,
	}

	// Write the issuer data to the specified path
	secret, err := vault.Logical().Write(fullPath, issuerData)

	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to write to path '%s': %v", fullPath, err)), nil
	}

	var successMsg string

	if rootMount != "" && rootIssuer != "" {
		csrData := secret.Data["csr"]

		signData := map[string]interface{}{
			"csr":    csrData,
			"format": "pem_bundle",
			"ttl":    ttl,
		}

		fullPath = fmt.Sprintf("%s/root/sign-intermediate", strings.TrimSuffix(rootMount, "/"))

		// Sign the intermediate certificate with the root issuer
		if secret, err = vault.Logical().Write(fullPath, signData); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to set root issuer '%s': %v", rootIssuer, err)), nil
		}

		chainData := secret.Data["ca_chain"].([]interface{})

		var certificateData string
		var certificateChain strings.Builder

		for i, cert := range chainData {
			if certStr, ok := cert.(string); ok {
				// The first certificate in the chain is the signed certificate
				if i == 0 {
					certificateData = certStr
				}
				if i > 0 {
					certificateChain.WriteString("\n")
				}
				certificateChain.WriteString(certStr)
			}
		}

		certificateChainStr := certificateChain.String()

		//certificateData := secret.Data["certificate"].(string)

		signedData := map[string]interface{}{
			"certificate": certificateData,
		}

		fullPath = fmt.Sprintf("%s/intermediate/set-signed", mount)

		// Write the intermediate certificate
		if _, err := vault.Logical().Write(fullPath, signedData); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to set intermediate issuer '%s': %v", issuerName, err)), nil
		}

		successMsg = fmt.Sprintf("Successfully created pki intermediate issuer with name '%s' on mount '%s'. Certificate chain data: \n%s", issuerName, mount, certificateChainStr)

		vaultAddress := vault.Address()

		crlData := map[string]interface{}{
			"issuing_certificates":    fmt.Sprintf("%s/v1/%s/ca", vaultAddress, mount),
			"crl_distribution_points": fmt.Sprintf("%s/v1/%s/crl", vaultAddress, mount),
		}

		fullPath = fmt.Sprintf("%s/config/urls", mount)

		// Write the crl information
		if _, err := vault.Logical().Write(fullPath, crlData); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to set crl for mount '%s': %v", mount, err)), nil
		}

	} else {
		// V1 API structure: secret.Data directly contains the key-value pairs
		certificateData := secret.Data["certificate"]

		successMsg = fmt.Sprintf("Successfully created pki issuer with name '%s' on mount '%s'. Certificate data: \n%s", issuerName, mount, certificateData)

	}

	logger.WithFields(log.Fields{
		"common_name": commonName,
		"issuer_name": issuerName,
		"ttl":         ttl,
	}).Info("Successfully created pki issuer")

	return mcp.NewToolResultText(successMsg), nil
}
