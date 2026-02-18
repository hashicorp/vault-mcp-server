// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package kv

import (
	"testing"

	"github.com/stretchr/testify/assert"
	log "github.com/sirupsen/logrus"
)

func TestReadSecret(t *testing.T) {
	logger := log.New()
	logger.SetLevel(log.ErrorLevel)

	t.Run("tool creation", func(t *testing.T) {
		tool := ReadSecret(logger)

		assert.Equal(t, "read_secret", tool.Tool.Name)
		assert.Contains(t, tool.Tool.Description, "Read a secret")
		assert.NotNil(t, tool.Handler)
	})

	t.Run("required parameters", func(t *testing.T) {
		tool := ReadSecret(logger)

		assert.Contains(t, tool.Tool.InputSchema.Required, "mount")
		assert.Contains(t, tool.Tool.InputSchema.Required, "path")
		assert.NotContains(t, tool.Tool.InputSchema.Required, "version")
	})

	t.Run("properties exist", func(t *testing.T) {
		tool := ReadSecret(logger)

		assert.NotNil(t, tool.Tool.InputSchema.Properties["mount"])
		assert.NotNil(t, tool.Tool.InputSchema.Properties["path"])
		assert.NotNil(t, tool.Tool.InputSchema.Properties["version"])
	})
}
