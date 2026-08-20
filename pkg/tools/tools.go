// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package tools

import (
	"github.com/hashicorp/vault-mcp-server/pkg/tools/kv"
	"github.com/hashicorp/vault-mcp-server/pkg/tools/pki"
	"github.com/hashicorp/vault-mcp-server/pkg/tools/sys"
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
)

func InitTools(hcServer *server.MCPServer, logger *log.Logger) {

	// Tools for Vault mount management
	listMountsTool := sys.ListMounts(logger)
	hcServer.AddTool(listMountsTool.Tool, listMountsTool.Handler)

	createMountTool := sys.CreateMount(logger)
	hcServer.AddTool(createMountTool.Tool, createMountTool.Handler)

	deleteMountTool := sys.DeleteMount(logger)
	hcServer.AddTool(deleteMountTool.Tool, deleteMountTool.Handler)

	// Tools for Vault replication status
	readReplicationStatusTool := sys.ReadReplicationStatus(logger)
	hcServer.AddTool(readReplicationStatusTool.Tool, readReplicationStatusTool.Handler)

	// Tools for Vault cluster health
	readClusterHealthTool := sys.ReadClusterHealth(logger)
	hcServer.AddTool(readClusterHealthTool.Tool, readClusterHealthTool.Handler)

	// Tools for Vault telemetry metrics
	readMetricsTool := sys.ReadMetrics(logger)
	hcServer.AddTool(readMetricsTool.Tool, readMetricsTool.Handler)

	// Tools for Vault host diagnostics
	readHostInfoTool := sys.ReadHostInfo(logger)
	hcServer.AddTool(readHostInfoTool.Tool, readHostInfoTool.Handler)

	// Tools for Vault lease management
	listLeasesTool := sys.ListLeases(logger)
	hcServer.AddTool(listLeasesTool.Tool, listLeasesTool.Handler)

	readLeaseTool := sys.ReadLease(logger)
	hcServer.AddTool(readLeaseTool.Tool, readLeaseTool.Handler)

	// Tools for KV secrets management
	listSecretsTool := kv.ListSecrets(logger)
	hcServer.AddTool(listSecretsTool.Tool, listSecretsTool.Handler)

	readSecretTool := kv.ReadSecret(logger)
	hcServer.AddTool(readSecretTool.Tool, readSecretTool.Handler)

	writeSecretTool := kv.WriteSecret(logger)
	hcServer.AddTool(writeSecretTool.Tool, writeSecretTool.Handler)

	deleteSecretTool := kv.DeleteSecret(logger)
	hcServer.AddTool(deleteSecretTool.Tool, deleteSecretTool.Handler)

	// Tools for PKI management
	enablePkiTool := pki.EnablePki(logger)
	hcServer.AddTool(enablePkiTool.Tool, enablePkiTool.Handler)

	createPkiIssuer := pki.CreatePkiIssuer(logger)
	hcServer.AddTool(createPkiIssuer.Tool, createPkiIssuer.Handler)

	listPkiIssuers := pki.ListPkiIssuers(logger)
	hcServer.AddTool(listPkiIssuers.Tool, listPkiIssuers.Handler)

	readPkiIssuer := pki.ReadPkiIssuer(logger)
	hcServer.AddTool(readPkiIssuer.Tool, readPkiIssuer.Handler)

	listPkiRoles := pki.ListPkiRoles(logger)
	hcServer.AddTool(listPkiRoles.Tool, listPkiRoles.Handler)

	readPkiRole := pki.ReadPkiRole(logger)
	hcServer.AddTool(readPkiRole.Tool, readPkiRole.Handler)

	createPkiRole := pki.CreatePkiRole(logger)
	hcServer.AddTool(createPkiRole.Tool, createPkiRole.Handler)

	deletePkiRole := pki.DeletePkiRole(logger)
	hcServer.AddTool(deletePkiRole.Tool, deletePkiRole.Handler)

	issuePkiCertificate := pki.IssuePkiCertificate(logger)
	hcServer.AddTool(issuePkiCertificate.Tool, issuePkiCertificate.Handler)
}
