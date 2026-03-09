// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package kv

import (
	"testing"

	"github.com/stretchr/testify/assert"
	log "github.com/sirupsen/logrus"
)

func TestReadSecretMetadata(t *testing.T) {
	logger := log.New()
	logger.SetLevel(log.ErrorLevel)

	t.Run("tool creation", func(t *testing.T) {
		tool := ReadSecretMetadata(logger)

		assert.Equal(t, "read_secret_metadata", tool.Tool.Name)
		assert.Contains(t, tool.Tool.Description, "metadata")
		assert.Contains(t, tool.Tool.Description, "KV v2")
		assert.NotNil(t, tool.Handler)
	})

	t.Run("annotations", func(t *testing.T) {
		tool := ReadSecretMetadata(logger)

		assert.NotNil(t, tool.Tool.Annotations.ReadOnlyHint)
		assert.True(t, *tool.Tool.Annotations.ReadOnlyHint)
		assert.NotNil(t, tool.Tool.Annotations.IdempotentHint)
		assert.True(t, *tool.Tool.Annotations.IdempotentHint)
	})

	t.Run("required parameters", func(t *testing.T) {
		tool := ReadSecretMetadata(logger)

		assert.Contains(t, tool.Tool.InputSchema.Required, "mount")
		assert.Contains(t, tool.Tool.InputSchema.Required, "path")
	})

	t.Run("properties exist", func(t *testing.T) {
		tool := ReadSecretMetadata(logger)

		assert.NotNil(t, tool.Tool.InputSchema.Properties["mount"])
		assert.NotNil(t, tool.Tool.InputSchema.Properties["path"])
	})
}
