// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package tools

import (
	"os"
	"strconv"

	"github.com/hashicorp/vault-mcp-server/pkg/tools/kv"
	"github.com/hashicorp/vault-mcp-server/pkg/tools/pki"
	"github.com/hashicorp/vault-mcp-server/pkg/tools/sys"
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
)

// vaultOperationsEnabled reports whether mutating (write / delete / create)
// tools should be registered. Controlled by the ENABLE_VAULT_OPERATIONS
// environment variable and defaults to false — when unset or false, only
// read-only tools are exposed, so a read-only Vault token cannot be tricked
// into attempting privileged operations that the surface should not offer.
func vaultOperationsEnabled() bool {
	v := os.Getenv("ENABLE_VAULT_OPERATIONS")
	if v == "" {
		return false
	}
	enabled, err := strconv.ParseBool(v)
	if err != nil {
		return false
	}
	return enabled
}

func InitTools(hcServer *server.MCPServer, logger *log.Logger) {
	writeEnabled := vaultOperationsEnabled()
	if !writeEnabled {
		logger.Info("ENABLE_VAULT_OPERATIONS is not true; registering read-only tools only")
	}

	// ---- Read-only tools (always registered) ----

	listMountsTool := sys.ListMounts(logger)
	hcServer.AddTool(listMountsTool.Tool, listMountsTool.Handler)

	listSecretsTool := kv.ListSecrets(logger)
	hcServer.AddTool(listSecretsTool.Tool, listSecretsTool.Handler)

	readSecretTool := kv.ReadSecret(logger)
	hcServer.AddTool(readSecretTool.Tool, readSecretTool.Handler)

	listPkiIssuers := pki.ListPkiIssuers(logger)
	hcServer.AddTool(listPkiIssuers.Tool, listPkiIssuers.Handler)

	readPkiIssuer := pki.ReadPkiIssuer(logger)
	hcServer.AddTool(readPkiIssuer.Tool, readPkiIssuer.Handler)

	listPkiRoles := pki.ListPkiRoles(logger)
	hcServer.AddTool(listPkiRoles.Tool, listPkiRoles.Handler)

	readPkiRole := pki.ReadPkiRole(logger)
	hcServer.AddTool(readPkiRole.Tool, readPkiRole.Handler)

	// ---- Mutating tools (only when ENABLE_VAULT_OPERATIONS=true) ----

	if !writeEnabled {
		return
	}

	createMountTool := sys.CreateMount(logger)
	hcServer.AddTool(createMountTool.Tool, createMountTool.Handler)

	deleteMountTool := sys.DeleteMount(logger)
	hcServer.AddTool(deleteMountTool.Tool, deleteMountTool.Handler)

	writeSecretTool := kv.WriteSecret(logger)
	hcServer.AddTool(writeSecretTool.Tool, writeSecretTool.Handler)

	deleteSecretTool := kv.DeleteSecret(logger)
	hcServer.AddTool(deleteSecretTool.Tool, deleteSecretTool.Handler)

	enablePkiTool := pki.EnablePki(logger)
	hcServer.AddTool(enablePkiTool.Tool, enablePkiTool.Handler)

	createPkiIssuer := pki.CreatePkiIssuer(logger)
	hcServer.AddTool(createPkiIssuer.Tool, createPkiIssuer.Handler)

	createPkiRole := pki.CreatePkiRole(logger)
	hcServer.AddTool(createPkiRole.Tool, createPkiRole.Handler)

	deletePkiRole := pki.DeletePkiRole(logger)
	hcServer.AddTool(deletePkiRole.Tool, deletePkiRole.Handler)

	issuePkiCertificate := pki.IssuePkiCertificate(logger)
	hcServer.AddTool(issuePkiCertificate.Tool, issuePkiCertificate.Handler)
}
