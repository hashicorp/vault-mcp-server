// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package tools

import (
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
)

func InitTools(mcpServer *server.MCPServer, logger *log.Logger) {
	listMountsTool := listMounts(logger)
	mcpServer.AddTool(listMountsTool.Tool, listMountsTool.Handler)

	createMountTool := createMount(logger)
	mcpServer.AddTool(createMountTool.Tool, createMountTool.Handler)

	deleteMountTool := deleteMount(logger)
	mcpServer.AddTool(deleteMountTool.Tool, deleteMountTool.Handler)

	listSecretsTool := listSecrets(logger)
	mcpServer.AddTool(listSecretsTool.Tool, listSecretsTool.Handler)

	readSecretTool := readSecret(logger)
	mcpServer.AddTool(readSecretTool.Tool, readSecretTool.Handler)

	writeSecretTool := writeSecret(logger)
	mcpServer.AddTool(writeSecretTool.Tool, writeSecretTool.Handler)
}
