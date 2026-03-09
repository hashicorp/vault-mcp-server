// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package kv

import (
	"testing"

	"github.com/stretchr/testify/assert"
	log "github.com/sirupsen/logrus"
)

func TestWriteSecret(t *testing.T) {
	logger := log.New()
	logger.SetLevel(log.ErrorLevel)

	t.Run("tool creation", func(t *testing.T) {
		tool := WriteSecret(logger)

		assert.Equal(t, "write_secret", tool.Tool.Name)
		assert.Contains(t, tool.Tool.Description, "Writes a secret")
		assert.NotNil(t, tool.Handler)
	})

	t.Run("annotations", func(t *testing.T) {
		tool := WriteSecret(logger)

		assert.NotNil(t, tool.Tool.Annotations.DestructiveHint)
		assert.True(t, *tool.Tool.Annotations.DestructiveHint)
		assert.NotNil(t, tool.Tool.Annotations.IdempotentHint)
		assert.False(t, *tool.Tool.Annotations.IdempotentHint)
	})

	t.Run("required parameters", func(t *testing.T) {
		tool := WriteSecret(logger)

		assert.Contains(t, tool.Tool.InputSchema.Required, "mount")
		assert.Contains(t, tool.Tool.InputSchema.Required, "path")
		assert.Contains(t, tool.Tool.InputSchema.Required, "data")
	})

	t.Run("properties exist", func(t *testing.T) {
		tool := WriteSecret(logger)

		assert.NotNil(t, tool.Tool.InputSchema.Properties["mount"])
		assert.NotNil(t, tool.Tool.InputSchema.Properties["path"])
		assert.NotNil(t, tool.Tool.InputSchema.Properties["data"])
		// key and value should no longer exist
		assert.Nil(t, tool.Tool.InputSchema.Properties["key"])
		assert.Nil(t, tool.Tool.InputSchema.Properties["value"])
	})
}
