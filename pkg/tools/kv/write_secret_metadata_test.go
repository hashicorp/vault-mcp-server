// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package kv

import (
	"testing"

	"github.com/stretchr/testify/assert"
	log "github.com/sirupsen/logrus"
)

func TestWriteSecretMetadata(t *testing.T) {
	logger := log.New()
	logger.SetLevel(log.ErrorLevel)

	t.Run("tool creation", func(t *testing.T) {
		tool := WriteSecretMetadata(logger)

		assert.Equal(t, "write_secret_metadata", tool.Tool.Name)
		assert.Contains(t, tool.Tool.Description, "metadata")
		assert.Contains(t, tool.Tool.Description, "KV v2")
		assert.NotNil(t, tool.Handler)
	})

	t.Run("annotations", func(t *testing.T) {
		tool := WriteSecretMetadata(logger)

		assert.NotNil(t, tool.Tool.Annotations.DestructiveHint)
		assert.True(t, *tool.Tool.Annotations.DestructiveHint)
		assert.NotNil(t, tool.Tool.Annotations.IdempotentHint)
		assert.False(t, *tool.Tool.Annotations.IdempotentHint)
	})

	t.Run("required parameters", func(t *testing.T) {
		tool := WriteSecretMetadata(logger)

		assert.Contains(t, tool.Tool.InputSchema.Required, "mount")
		assert.Contains(t, tool.Tool.InputSchema.Required, "path")
		// Optional params should not be required
		assert.NotContains(t, tool.Tool.InputSchema.Required, "max_versions")
		assert.NotContains(t, tool.Tool.InputSchema.Required, "cas_required")
		assert.NotContains(t, tool.Tool.InputSchema.Required, "delete_version_after")
		assert.NotContains(t, tool.Tool.InputSchema.Required, "custom_metadata")
	})

	t.Run("properties exist", func(t *testing.T) {
		tool := WriteSecretMetadata(logger)

		assert.NotNil(t, tool.Tool.InputSchema.Properties["mount"])
		assert.NotNil(t, tool.Tool.InputSchema.Properties["path"])
		assert.NotNil(t, tool.Tool.InputSchema.Properties["max_versions"])
		assert.NotNil(t, tool.Tool.InputSchema.Properties["cas_required"])
		assert.NotNil(t, tool.Tool.InputSchema.Properties["delete_version_after"])
		assert.NotNil(t, tool.Tool.InputSchema.Properties["custom_metadata"])
	})
}
