// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package toolsets

import (
	"slices"
	"strings"
)

// individualToolsMarker is an internal marker indicating individual tool mode.
const individualToolsMarker = "__individual_tools__"

// ToolToToolset maps each tool name to its toolset.
var ToolToToolset = map[string]string{
	// Sys tools
	"list_mounts":  Sys,
	"create_mount": Sys,
	"delete_mount": Sys,

	// KV tools
	"list_secrets":            KV,
	"read_secret":             KV,
	"write_secret":            KV,
	"delete_secret":           KV,
	"read_secret_metadata":    KV,
	"write_secret_metadata":   KV,
	"undelete_secret":         KV,
	"destroy_secret_versions": KV,
	"patch_secret":            KV,

	// PKI tools
	"enable_pki":            PKI,
	"create_pki_issuer":     PKI,
	"list_pki_issuers":      PKI,
	"read_pki_issuer":       PKI,
	"list_pki_roles":        PKI,
	"read_pki_role":         PKI,
	"create_pki_role":       PKI,
	"delete_pki_role":       PKI,
	"issue_pki_certificate": PKI,
}

// IsToolEnabled checks whether a tool should be registered given the enabled toolsets.
// If "all" is in the list, all tools are enabled.
// If the individualToolsMarker is present, only exact tool name matches are enabled.
// Otherwise, the tool is enabled if its parent toolset is in the enabled list.
func IsToolEnabled(toolName string, enabledToolsets []string) bool {
	if slices.Contains(enabledToolsets, All) {
		return true
	}

	if slices.Contains(enabledToolsets, individualToolsMarker) {
		return slices.Contains(enabledToolsets, toolName)
	}

	toolset, ok := ToolToToolset[toolName]
	if !ok {
		return false
	}
	return slices.Contains(enabledToolsets, toolset)
}

// GetAllValidToolNames returns a set of all known tool names.
func GetAllValidToolNames() map[string]bool {
	names := make(map[string]bool, len(ToolToToolset))
	for name := range ToolToToolset {
		names[name] = true
	}
	return names
}

// ParseIndividualTools validates tool names and returns valid and invalid lists.
func ParseIndividualTools(tools []string) (valid, invalid []string) {
	allNames := GetAllValidToolNames()
	for _, name := range tools {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if allNames[name] {
			valid = append(valid, name)
		} else {
			invalid = append(invalid, name)
		}
	}
	return valid, invalid
}

// EnableIndividualTools creates an enabledToolsets slice for individual tool mode.
// It prepends the internal marker so IsToolEnabled knows to check exact names.
func EnableIndividualTools(tools []string) []string {
	result := make([]string, 0, len(tools)+1)
	result = append(result, individualToolsMarker)
	result = append(result, tools...)
	return result
}
