// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
)

func InitTools(hcServer *server.MCPServer, logger *log.Logger) {
	listMountsTool := ListMounts(logger)
	hcServer.AddTool(listMountsTool.Tool, listMountsTool.Handler)

	createMountTool := CreateMount(logger)
	hcServer.AddTool(createMountTool.Tool, createMountTool.Handler)

	deleteMountTool := DeleteMount(logger)
	hcServer.AddTool(deleteMountTool.Tool, deleteMountTool.Handler)

	listSecretsTool := ListSecrets(logger)
	hcServer.AddTool(listSecretsTool.Tool, listSecretsTool.Handler)

	readSecretTool := ReadSecret(logger)
	hcServer.AddTool(readSecretTool.Tool, readSecretTool.Handler)

	writeSecretTool := WriteSecret(logger)
	hcServer.AddTool(writeSecretTool.Tool, writeSecretTool.Handler)

	deleteSecretTool := DeleteSecret(logger)
	hcServer.AddTool(deleteSecretTool.Tool, deleteSecretTool.Handler)

	// Authentication method tools
	listAuthMethodsTool := ListAuthMethods(logger)
	hcServer.AddTool(listAuthMethodsTool.Tool, listAuthMethodsTool.Handler)

	enableAuthMethodTool := EnableAuthMethod(logger)
	hcServer.AddTool(enableAuthMethodTool.Tool, enableAuthMethodTool.Handler)

	disableAuthMethodTool := DisableAuthMethod(logger)
	hcServer.AddTool(disableAuthMethodTool.Tool, disableAuthMethodTool.Handler)

	readAuthMethodTool := ReadAuthMethod(logger)
	hcServer.AddTool(readAuthMethodTool.Tool, readAuthMethodTool.Handler)
}
