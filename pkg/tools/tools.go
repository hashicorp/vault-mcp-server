// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package tools

import (
	"github.com/hashicorp/vault-mcp-server/pkg/auth"
	toolauth "github.com/hashicorp/vault-mcp-server/pkg/tools/auth"
	"github.com/hashicorp/vault-mcp-server/pkg/tools/kv"
	"github.com/hashicorp/vault-mcp-server/pkg/tools/pki"
	"github.com/hashicorp/vault-mcp-server/pkg/tools/sys"
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
)

// InitLoginTools registers the vault_login_subject, vault_login_actor, and
// vault_auth_status tools. onReady is called when authentication completes.
func InitLoginTools(hcServer *server.MCPServer, cfg auth.AuthConfig, onReady func(*auth.TokenSource), logger *log.Logger) func() {
	loginSubject, loginActor, authStatus, closeSession := toolauth.NewLoginTools(cfg, onReady, logger)
	hcServer.AddTool(loginSubject.Tool, loginSubject.Handler)
	hcServer.AddTool(loginActor.Tool, loginActor.Handler)
	hcServer.AddTool(authStatus.Tool, authStatus.Handler)
	return closeSession
}

func InitTools(hcServer *server.MCPServer, logger *log.Logger) {

	// Tools for Vault mount management
	listMountsTool := sys.ListMounts(logger)
	hcServer.AddTool(listMountsTool.Tool, listMountsTool.Handler)

	createMountTool := sys.CreateMount(logger)
	hcServer.AddTool(createMountTool.Tool, createMountTool.Handler)

	deleteMountTool := sys.DeleteMount(logger)
	hcServer.AddTool(deleteMountTool.Tool, deleteMountTool.Handler)

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
