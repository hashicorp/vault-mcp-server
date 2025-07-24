// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
)

func InitTools(hcServer *server.MCPServer, logger *log.Logger) {
	// Mount management tools
	listMountsTool := ListMounts(logger)
	hcServer.AddTool(listMountsTool.Tool, listMountsTool.Handler)

	createMountTool := CreateMount(logger)
	hcServer.AddTool(createMountTool.Tool, createMountTool.Handler)

	deleteMountTool := DeleteMount(logger)
	hcServer.AddTool(deleteMountTool.Tool, deleteMountTool.Handler)

	// Secret management tools
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

	// Token management tools
	generateTokenTool := GenerateToken(logger)
	hcServer.AddTool(generateTokenTool.Tool, generateTokenTool.Handler)

	// System health and status tools
	getHealthStatusTool := GetHealthStatus(logger)
	hcServer.AddTool(getHealthStatusTool.Tool, getHealthStatusTool.Handler)

	getSealStatusTool := GetSealStatus(logger)
	hcServer.AddTool(getSealStatusTool.Tool, getSealStatusTool.Handler)

	// Audit device tools
	listAuditDevicesTool := ListAuditDevices(logger)
	hcServer.AddTool(listAuditDevicesTool.Tool, listAuditDevicesTool.Handler)

	enableAuditDeviceTool := EnableAuditDevice(logger)
	hcServer.AddTool(enableAuditDeviceTool.Tool, enableAuditDeviceTool.Handler)

	disableAuditDeviceTool := DisableAuditDevice(logger)
	hcServer.AddTool(disableAuditDeviceTool.Tool, disableAuditDeviceTool.Handler)

	// Policy management tools
	listPoliciesTool := ListPolicies(logger)
	hcServer.AddTool(listPoliciesTool.Tool, listPoliciesTool.Handler)

	getPolicyTool := GetPolicy(logger)
	hcServer.AddTool(getPolicyTool.Tool, getPolicyTool.Handler)

	createPolicyTool := CreatePolicy(logger)
	hcServer.AddTool(createPolicyTool.Tool, createPolicyTool.Handler)

	deletePolicyTool := DeletePolicy(logger)
	hcServer.AddTool(deletePolicyTool.Tool, deletePolicyTool.Handler)

	// CORS configuration tools
	updateCORSConfigTool := UpdateCORSConfig(logger)
	hcServer.AddTool(updateCORSConfigTool.Tool, updateCORSConfigTool.Handler)

	// UI configuration tools
	getUIHeadersTool := GetUIHeaders(logger)
	hcServer.AddTool(getUIHeadersTool.Tool, getUIHeadersTool.Handler)

	// Security health analysis orchestration tool
	analyzeSecurityHealthTool := AnalyzeSecurityHealth(logger)
	hcServer.AddTool(analyzeSecurityHealthTool.Tool, analyzeSecurityHealthTool.Handler)

	// Advanced security monitoring tools
	getRootGenerationStatusTool := GetRootGenerationStatus(logger)
	hcServer.AddTool(getRootGenerationStatusTool.Tool, getRootGenerationStatusTool.Handler)

	getRateLimitQuotasTool := GetRateLimitQuotas(logger)
	hcServer.AddTool(getRateLimitQuotasTool.Tool, getRateLimitQuotasTool.Handler)

	getLeaseCountQuotasTool := GetLeaseCountQuotas(logger)
	hcServer.AddTool(getLeaseCountQuotasTool.Tool, getLeaseCountQuotasTool.Handler)

	getReplicationStatusTool := GetReplicationStatus(logger)
	hcServer.AddTool(getReplicationStatusTool.Tool, getReplicationStatusTool.Handler)

	getSanitizedConfigTool := GetSanitizedConfig(logger)
	hcServer.AddTool(getSanitizedConfigTool.Tool, getSanitizedConfigTool.Handler)

	getCORSConfigTool := GetCORSConfig(logger)
	hcServer.AddTool(getCORSConfigTool.Tool, getCORSConfigTool.Handler)

	getLeaseCountsTool := GetLeaseCounts(logger)
	hcServer.AddTool(getLeaseCountsTool.Tool, getLeaseCountsTool.Handler)

	getCurrentTokenCapabilitiesTool := GetCurrentTokenCapabilities(logger)
	hcServer.AddTool(getCurrentTokenCapabilitiesTool.Tool, getCurrentTokenCapabilitiesTool.Handler)

	// URL parsing tools
	parseVaultUIURLTool := ParseVaultUIURLTool(logger)
	hcServer.AddTool(parseVaultUIURLTool.Tool, parseVaultUIURLTool.Handler)

}
