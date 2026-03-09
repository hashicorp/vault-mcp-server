// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package kv

import (
	"testing"

	"github.com/stretchr/testify/assert"
	log "github.com/sirupsen/logrus"
)

func TestListSecrets(t *testing.T) {
	logger := log.New()
	logger.SetLevel(log.ErrorLevel)

	t.Run("tool creation", func(t *testing.T) {
		tool := ListSecrets(logger)

		assert.Equal(t, "list_secrets", tool.Tool.Name)
		assert.Contains(t, tool.Tool.Description, "List secrets")
		assert.NotNil(t, tool.Handler)
	})

	t.Run("annotations", func(t *testing.T) {
		tool := ListSecrets(logger)

		assert.NotNil(t, tool.Tool.Annotations.ReadOnlyHint)
		assert.True(t, *tool.Tool.Annotations.ReadOnlyHint)
	})

	t.Run("required parameters", func(t *testing.T) {
		tool := ListSecrets(logger)

		assert.Contains(t, tool.Tool.InputSchema.Required, "mount")
		assert.NotContains(t, tool.Tool.InputSchema.Required, "path")
	})

	t.Run("properties exist", func(t *testing.T) {
		tool := ListSecrets(logger)

		assert.NotNil(t, tool.Tool.InputSchema.Properties["mount"])
		assert.NotNil(t, tool.Tool.InputSchema.Properties["path"])
	})
}
