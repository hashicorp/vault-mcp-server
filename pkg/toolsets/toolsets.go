// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package toolsets

import (
	"fmt"
	"slices"
	"strings"
)

const (
	// Sys represents mount management tools (list/create/delete mounts).
	Sys = "sys"
	// KV represents KV secrets tools (read/write/delete/patch/metadata/etc.).
	KV = "kv"
	// PKI represents PKI management tools (issuers/roles/certificates).
	PKI = "pki"

	// All activates all toolsets.
	All = "all"
	// Default activates the default set of toolsets.
	Default = "default"
)

// Toolset describes a named group of tools.
type Toolset struct {
	Name        string
	Description string
}

// availableToolsets lists the concrete toolsets.
var availableToolsets = []Toolset{
	{Name: Sys, Description: "Mount management (list/create/delete mounts)"},
	{Name: KV, Description: "KV secrets (read/write/delete/patch/metadata/etc.)"},
	{Name: PKI, Description: "PKI management (issuers/roles/certificates)"},
}

// AvailableToolsets returns the list of concrete toolsets.
func AvailableToolsets() []Toolset {
	return availableToolsets
}

// DefaultToolsets returns the default set of enabled toolset names.
func DefaultToolsets() []string {
	return []string{Sys, KV, PKI}
}

// GetValidToolsetNames returns all valid toolset names including special keywords.
func GetValidToolsetNames() map[string]bool {
	valid := map[string]bool{
		All:      true,
		Default:  true,
	}
	for _, ts := range availableToolsets {
		valid[ts.Name] = true
	}
	return valid
}

// CleanToolsets deduplicates, trims, and validates toolset names.
// It returns the cleaned list and any invalid names found.
func CleanToolsets(input []string) (cleaned, invalid []string) {
	seen := make(map[string]bool)
	valid := GetValidToolsetNames()

	for _, name := range input {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if !valid[name] {
			invalid = append(invalid, name)
			continue
		}
		if !seen[name] {
			seen[name] = true
			cleaned = append(cleaned, name)
		}
	}
	return cleaned, invalid
}

// ExpandDefaultToolset replaces the "default" keyword with the actual default toolsets.
func ExpandDefaultToolset(input []string) []string {
	var result []string
	seen := make(map[string]bool)

	for _, name := range input {
		if name == Default {
			for _, d := range DefaultToolsets() {
				if !seen[d] {
					seen[d] = true
					result = append(result, d)
				}
			}
		} else {
			if !seen[name] {
				seen[name] = true
				result = append(result, name)
			}
		}
	}
	return result
}

// ContainsToolset checks if a toolset name is present in the list.
func ContainsToolset(toolsets []string, name string) bool {
	return slices.Contains(toolsets, name)
}

// GenerateToolsetsHelp returns help text for the --toolsets flag.
func GenerateToolsetsHelp() string {
	var sb strings.Builder
	sb.WriteString("Comma-separated list of toolsets to enable.\n")
	sb.WriteString("Special values: 'all' (enable all), 'default' (enable default set).\n")
	sb.WriteString("Available toolsets:\n")
	for _, ts := range availableToolsets {
		fmt.Fprintf(&sb, "  - %s: %s\n", ts.Name, ts.Description)
	}
	return sb.String()
}

// GenerateToolsHelp returns help text for the --tools flag.
func GenerateToolsHelp() string {
	var sb strings.Builder
	sb.WriteString("Comma-separated list of individual tool names to enable.\n")
	sb.WriteString("When specified, only the listed tools are enabled (overrides --toolsets).\n")
	sb.WriteString("Use the tool names as they appear in the MCP tool list.\n")
	return sb.String()
}
