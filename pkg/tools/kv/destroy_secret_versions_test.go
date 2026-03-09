// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package kv

import (
	"testing"

	"github.com/stretchr/testify/assert"
	log "github.com/sirupsen/logrus"
)

func TestDestroySecretVersions(t *testing.T) {
	logger := log.New()
	logger.SetLevel(log.ErrorLevel)

	t.Run("tool creation", func(t *testing.T) {
		tool := DestroySecretVersions(logger)

		assert.Equal(t, "destroy_secret_versions", tool.Tool.Name)
		assert.Contains(t, tool.Tool.Description, "Permanently destroy")
		assert.Contains(t, tool.Tool.Description, "KV v2")
		assert.NotNil(t, tool.Handler)
	})

	t.Run("annotations", func(t *testing.T) {
		tool := DestroySecretVersions(logger)

		assert.NotNil(t, tool.Tool.Annotations.DestructiveHint)
		assert.True(t, *tool.Tool.Annotations.DestructiveHint)
		assert.NotNil(t, tool.Tool.Annotations.IdempotentHint)
		assert.True(t, *tool.Tool.Annotations.IdempotentHint)
	})

	t.Run("required parameters", func(t *testing.T) {
		tool := DestroySecretVersions(logger)

		assert.Contains(t, tool.Tool.InputSchema.Required, "mount")
		assert.Contains(t, tool.Tool.InputSchema.Required, "path")
		assert.Contains(t, tool.Tool.InputSchema.Required, "versions")
	})

	t.Run("properties exist", func(t *testing.T) {
		tool := DestroySecretVersions(logger)

		assert.NotNil(t, tool.Tool.InputSchema.Properties["mount"])
		assert.NotNil(t, tool.Tool.InputSchema.Properties["path"])
		assert.NotNil(t, tool.Tool.InputSchema.Properties["versions"])
	})
}
