// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
)

func InitTools(hcServer *server.MCPServer, logger *log.Logger) {

	// Tools for Vault mount management
	listMountsTool := ListMounts(logger)
	hcServer.AddTool(listMountsTool.Tool, listMountsTool.Handler)

	createMountTool := CreateMount(logger)
	hcServer.AddTool(createMountTool.Tool, createMountTool.Handler)

	deleteMountTool := DeleteMount(logger)
	hcServer.AddTool(deleteMountTool.Tool, deleteMountTool.Handler)

	// Tools for KV secrets management
	listSecretsTool := ListSecrets(logger)
	hcServer.AddTool(listSecretsTool.Tool, listSecretsTool.Handler)

	readSecretTool := ReadSecret(logger)
	hcServer.AddTool(readSecretTool.Tool, readSecretTool.Handler)

	writeSecretTool := WriteSecret(logger)
	hcServer.AddTool(writeSecretTool.Tool, writeSecretTool.Handler)

	deleteSecretTool := DeleteSecret(logger)
	hcServer.AddTool(deleteSecretTool.Tool, deleteSecretTool.Handler)

	// Tools for PKI management
	enablePkiTool := EnablePki(logger)
	hcServer.AddTool(enablePkiTool.Tool, enablePkiTool.Handler)

	createPkiIssuer := CreatePkiIssuer(logger)
	hcServer.AddTool(createPkiIssuer.Tool, createPkiIssuer.Handler)

	listPkiIssuers := ListPkiIssuers(logger)
	hcServer.AddTool(listPkiIssuers.Tool, listPkiIssuers.Handler)

	readPkiIssuer := ReadPkiIssuer(logger)
	hcServer.AddTool(readPkiIssuer.Tool, readPkiIssuer.Handler)

	listPkiRoles := ListPkiRoles(logger)
	hcServer.AddTool(listPkiRoles.Tool, listPkiRoles.Handler)

	readPkiRole := ReadPkiRole(logger)
	hcServer.AddTool(readPkiRole.Tool, readPkiRole.Handler)

	createPkiRole := CreatePkiRole(logger)
	hcServer.AddTool(createPkiRole.Tool, createPkiRole.Handler)

	deletePkiRole := DeletePkiRole(logger)
	hcServer.AddTool(deletePkiRole.Tool, deletePkiRole.Handler)

	issuePkiCertificate := IssuePkiCertificate(logger)
	hcServer.AddTool(issuePkiCertificate.Tool, issuePkiCertificate.Handler)
}

func ToBoolPtr(b bool) *bool {
	return &b
}
