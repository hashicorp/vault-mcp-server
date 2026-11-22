// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package toolsets

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsToolEnabled_All(t *testing.T) {
	enabled := []string{"all"}
	assert.True(t, IsToolEnabled("read_secret", enabled))
	assert.True(t, IsToolEnabled("list_mounts", enabled))
	assert.True(t, IsToolEnabled("enable_pki", enabled))
}

func TestIsToolEnabled_SpecificToolset(t *testing.T) {
	enabled := []string{"kv"}
	assert.True(t, IsToolEnabled("read_secret", enabled))
	assert.True(t, IsToolEnabled("list_secrets", enabled))
	assert.False(t, IsToolEnabled("enable_pki", enabled))
	assert.False(t, IsToolEnabled("list_mounts", enabled))
}

func TestIsToolEnabled_MultipleToolsets(t *testing.T) {
	enabled := []string{"kv", "sys"}
	assert.True(t, IsToolEnabled("read_secret", enabled))
	assert.True(t, IsToolEnabled("list_mounts", enabled))
	assert.False(t, IsToolEnabled("enable_pki", enabled))
}

func TestIsToolEnabled_IndividualTools(t *testing.T) {
	enabled := EnableIndividualTools([]string{"read_secret", "list_secrets"})
	assert.True(t, IsToolEnabled("read_secret", enabled))
	assert.True(t, IsToolEnabled("list_secrets", enabled))
	assert.False(t, IsToolEnabled("write_secret", enabled))
	assert.False(t, IsToolEnabled("list_mounts", enabled))
}

func TestIsToolEnabled_Default(t *testing.T) {
	enabled := ExpandDefaultToolset([]string{"default"})
	assert.True(t, IsToolEnabled("read_secret", enabled))
	assert.True(t, IsToolEnabled("list_mounts", enabled))
	assert.True(t, IsToolEnabled("enable_pki", enabled))
}

func TestIsToolEnabled_UnknownTool(t *testing.T) {
	enabled := []string{"kv"}
	assert.False(t, IsToolEnabled("nonexistent_tool", enabled))
}

func TestToolToToolset_Complete(t *testing.T) {
	assert.Len(t, ToolToToolset, 21, "expected 21 tools mapped")

	// Verify sys tools
	assert.Equal(t, Sys, ToolToToolset["list_mounts"])
	assert.Equal(t, Sys, ToolToToolset["create_mount"])
	assert.Equal(t, Sys, ToolToToolset["delete_mount"])

	// Verify kv tools
	kvTools := []string{
		"list_secrets", "read_secret", "write_secret", "delete_secret",
		"read_secret_metadata", "write_secret_metadata",
		"undelete_secret", "destroy_secret_versions", "patch_secret",
	}
	for _, tool := range kvTools {
		assert.Equal(t, KV, ToolToToolset[tool], "tool %s should be in KV toolset", tool)
	}

	// Verify pki tools
	pkiTools := []string{
		"enable_pki", "create_pki_issuer", "list_pki_issuers", "read_pki_issuer",
		"list_pki_roles", "read_pki_role", "create_pki_role", "delete_pki_role",
		"issue_pki_certificate",
	}
	for _, tool := range pkiTools {
		assert.Equal(t, PKI, ToolToToolset[tool], "tool %s should be in PKI toolset", tool)
	}
}

func TestParseIndividualTools(t *testing.T) {
	t.Run("valid tools", func(t *testing.T) {
		valid, invalid := ParseIndividualTools([]string{"read_secret", "list_mounts"})
		assert.Equal(t, []string{"read_secret", "list_mounts"}, valid)
		assert.Empty(t, invalid)
	})

	t.Run("mix of valid and invalid", func(t *testing.T) {
		valid, invalid := ParseIndividualTools([]string{"read_secret", "fake_tool"})
		assert.Equal(t, []string{"read_secret"}, valid)
		assert.Equal(t, []string{"fake_tool"}, invalid)
	})

	t.Run("trims whitespace", func(t *testing.T) {
		valid, invalid := ParseIndividualTools([]string{" read_secret ", ""})
		assert.Equal(t, []string{"read_secret"}, valid)
		assert.Empty(t, invalid)
	})
}

func TestGetAllValidToolNames(t *testing.T) {
	names := GetAllValidToolNames()
	require.Len(t, names, 21)
	assert.True(t, names["read_secret"])
	assert.True(t, names["list_mounts"])
	assert.True(t, names["enable_pki"])
	assert.False(t, names["nonexistent"])
}

func TestEnableIndividualTools(t *testing.T) {
	result := EnableIndividualTools([]string{"read_secret", "list_mounts"})
	assert.Equal(t, []string{individualToolsMarker, "read_secret", "list_mounts"}, result)
}
