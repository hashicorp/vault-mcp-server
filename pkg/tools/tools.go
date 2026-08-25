// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package tools

import (
	"github.com/hashicorp/vault-mcp-server/pkg/tools/kv"
	"github.com/hashicorp/vault-mcp-server/pkg/tools/pki"
	"github.com/hashicorp/vault-mcp-server/pkg/tools/sys"
	"github.com/hashicorp/vault-mcp-server/pkg/toolsets"
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
)

// RegisterTools registers all enabled tools on the MCP server.
// The enabledToolsets parameter controls which tools are registered.
func RegisterTools(hcServer *server.MCPServer, logger *log.Logger, enabledToolsets []string) {

	// Tools for Vault mount management
	if toolsets.IsToolEnabled("list_mounts", enabledToolsets) {
		tool := sys.ListMounts(logger)
		hcServer.AddTool(tool.Tool, tool.Handler)
	}

	if toolsets.IsToolEnabled("create_mount", enabledToolsets) {
		tool := sys.CreateMount(logger)
		hcServer.AddTool(tool.Tool, tool.Handler)
	}

	if toolsets.IsToolEnabled("delete_mount", enabledToolsets) {
		tool := sys.DeleteMount(logger)
		hcServer.AddTool(tool.Tool, tool.Handler)
	}

	// Tools for KV secrets management
	if toolsets.IsToolEnabled("list_secrets", enabledToolsets) {
		tool := kv.ListSecrets(logger)
		hcServer.AddTool(tool.Tool, tool.Handler)
	}

	if toolsets.IsToolEnabled("read_secret", enabledToolsets) {
		tool := kv.ReadSecret(logger)
		hcServer.AddTool(tool.Tool, tool.Handler)
	}

	if toolsets.IsToolEnabled("write_secret", enabledToolsets) {
		tool := kv.WriteSecret(logger)
		hcServer.AddTool(tool.Tool, tool.Handler)
	}

	if toolsets.IsToolEnabled("delete_secret", enabledToolsets) {
		tool := kv.DeleteSecret(logger)
		hcServer.AddTool(tool.Tool, tool.Handler)
	}

	// Tools for PKI management
	if toolsets.IsToolEnabled("enable_pki", enabledToolsets) {
		tool := pki.EnablePki(logger)
		hcServer.AddTool(tool.Tool, tool.Handler)
	}

	if toolsets.IsToolEnabled("create_pki_issuer", enabledToolsets) {
		tool := pki.CreatePkiIssuer(logger)
		hcServer.AddTool(tool.Tool, tool.Handler)
	}

	if toolsets.IsToolEnabled("list_pki_issuers", enabledToolsets) {
		tool := pki.ListPkiIssuers(logger)
		hcServer.AddTool(tool.Tool, tool.Handler)
	}

	if toolsets.IsToolEnabled("read_pki_issuer", enabledToolsets) {
		tool := pki.ReadPkiIssuer(logger)
		hcServer.AddTool(tool.Tool, tool.Handler)
	}

	if toolsets.IsToolEnabled("list_pki_roles", enabledToolsets) {
		tool := pki.ListPkiRoles(logger)
		hcServer.AddTool(tool.Tool, tool.Handler)
	}

	if toolsets.IsToolEnabled("read_pki_role", enabledToolsets) {
		tool := pki.ReadPkiRole(logger)
		hcServer.AddTool(tool.Tool, tool.Handler)
	}

	if toolsets.IsToolEnabled("create_pki_role", enabledToolsets) {
		tool := pki.CreatePkiRole(logger)
		hcServer.AddTool(tool.Tool, tool.Handler)
	}

	if toolsets.IsToolEnabled("delete_pki_role", enabledToolsets) {
		tool := pki.DeletePkiRole(logger)
		hcServer.AddTool(tool.Tool, tool.Handler)
	}

	if toolsets.IsToolEnabled("issue_pki_certificate", enabledToolsets) {
		tool := pki.IssuePkiCertificate(logger)
		hcServer.AddTool(tool.Tool, tool.Handler)
	}
}
