// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package toolsets

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultToolsets(t *testing.T) {
	defaults := DefaultToolsets()
	assert.Contains(t, defaults, Sys)
	assert.Contains(t, defaults, KV)
	assert.Contains(t, defaults, PKI)
	assert.Len(t, defaults, 3)
}

func TestCleanToolsets(t *testing.T) {
	t.Run("deduplicates and trims", func(t *testing.T) {
		cleaned, invalid := CleanToolsets([]string{" kv ", "kv", "sys", " sys"})
		assert.Equal(t, []string{"kv", "sys"}, cleaned)
		assert.Empty(t, invalid)
	})

	t.Run("detects invalid names", func(t *testing.T) {
		cleaned, invalid := CleanToolsets([]string{"kv", "bogus", "nope"})
		assert.Equal(t, []string{"kv"}, cleaned)
		assert.Equal(t, []string{"bogus", "nope"}, invalid)
	})

	t.Run("skips empty strings", func(t *testing.T) {
		cleaned, invalid := CleanToolsets([]string{"", " ", "sys"})
		assert.Equal(t, []string{"sys"}, cleaned)
		assert.Empty(t, invalid)
	})

	t.Run("accepts special keywords", func(t *testing.T) {
		cleaned, invalid := CleanToolsets([]string{"all", "default"})
		assert.Equal(t, []string{"all", "default"}, cleaned)
		assert.Empty(t, invalid)
	})
}

func TestExpandDefaultToolset(t *testing.T) {
	t.Run("expands default", func(t *testing.T) {
		result := ExpandDefaultToolset([]string{"default"})
		assert.Equal(t, []string{"sys", "kv", "pki"}, result)
	})

	t.Run("preserves non-default", func(t *testing.T) {
		result := ExpandDefaultToolset([]string{"kv"})
		assert.Equal(t, []string{"kv"}, result)
	})

	t.Run("deduplicates after expansion", func(t *testing.T) {
		result := ExpandDefaultToolset([]string{"kv", "default"})
		assert.Equal(t, []string{"kv", "sys", "pki"}, result)
	})
}

func TestContainsToolset(t *testing.T) {
	assert.True(t, ContainsToolset([]string{"sys", "kv"}, "kv"))
	assert.False(t, ContainsToolset([]string{"sys", "kv"}, "pki"))
	assert.False(t, ContainsToolset(nil, "kv"))
}

func TestGetValidToolsetNames(t *testing.T) {
	valid := GetValidToolsetNames()
	require.Len(t, valid, 5)
	assert.True(t, valid[Sys])
	assert.True(t, valid[KV])
	assert.True(t, valid[PKI])
	assert.True(t, valid[All])
	assert.True(t, valid[Default])
}

func TestAvailableToolsets(t *testing.T) {
	ts := AvailableToolsets()
	assert.Len(t, ts, 3)
	names := make([]string, len(ts))
	for i, toolset := range ts {
		names[i] = toolset.Name
	}
	assert.Contains(t, names, Sys)
	assert.Contains(t, names, KV)
	assert.Contains(t, names, PKI)
}

func TestGenerateToolsetsHelp(t *testing.T) {
	help := GenerateToolsetsHelp()
	assert.Contains(t, help, "sys")
	assert.Contains(t, help, "kv")
	assert.Contains(t, help, "pki")
	assert.Contains(t, help, "all")
}

func TestGenerateToolsHelp(t *testing.T) {
	help := GenerateToolsHelp()
	assert.Contains(t, help, "individual tool names")
}
