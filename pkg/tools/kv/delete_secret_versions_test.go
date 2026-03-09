// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package kv

import (
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestDeleteSecretVersions(t *testing.T) {
	logger := log.New()
	logger.SetLevel(log.ErrorLevel)

	t.Run("tool creation", func(t *testing.T) {
		tool := DeleteSecretVersions(logger)

		assert.Equal(t, "delete_secret_versions", tool.Tool.Name)
		assert.Contains(t, tool.Tool.Description, "Soft-delete")
		assert.NotNil(t, tool.Handler)
	})

	t.Run("annotations", func(t *testing.T) {
		tool := DeleteSecretVersions(logger)

		assert.NotNil(t, tool.Tool.Annotations.DestructiveHint)
		assert.True(t, *tool.Tool.Annotations.DestructiveHint)
		assert.NotNil(t, tool.Tool.Annotations.IdempotentHint)
		assert.True(t, *tool.Tool.Annotations.IdempotentHint)
	})

	t.Run("required parameters", func(t *testing.T) {
		tool := DeleteSecretVersions(logger)

		assert.Contains(t, tool.Tool.InputSchema.Required, "mount")
		assert.Contains(t, tool.Tool.InputSchema.Required, "path")
		assert.NotContains(t, tool.Tool.InputSchema.Required, "versions")
	})

	t.Run("properties exist", func(t *testing.T) {
		tool := DeleteSecretVersions(logger)

		assert.NotNil(t, tool.Tool.InputSchema.Properties["mount"])
		assert.NotNil(t, tool.Tool.InputSchema.Properties["path"])
		assert.NotNil(t, tool.Tool.InputSchema.Properties["versions"])
	})
}
