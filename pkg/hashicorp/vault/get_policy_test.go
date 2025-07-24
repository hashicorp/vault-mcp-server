// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"os"
	"testing"

	log "github.com/sirupsen/logrus"
)

func TestGetPolicy(t *testing.T) {
	logger := log.New()
	logger.SetOutput(os.Stdout)
	tool := GetPolicy(logger)

	// Verify tool structure
	if tool.Tool.Name != "get_policy" {
		t.Errorf("Expected tool name 'get_policy', got %s", tool.Tool.Name)
	}

	if tool.Tool.Description == "" {
		t.Errorf("Expected non-empty description")
	}

	if tool.Handler == nil {
		t.Errorf("Expected non-nil handler")
	}

	// Verify the tool has the expected input parameters
	if len(tool.Tool.InputSchema.Properties) < 1 {
		t.Errorf("Expected at least 1 input parameter, got %d", len(tool.Tool.InputSchema.Properties))
	}

	// Check that required parameter 'name' exists
	_, exists := tool.Tool.InputSchema.Properties["name"]
	if !exists {
		t.Errorf("Expected 'name' parameter to exist")
	}

	// Check that 'name' is required
	nameRequired := false
	for _, required := range tool.Tool.InputSchema.Required {
		if required == "name" {
			nameRequired = true
			break
		}
	}
	if !nameRequired {
		t.Errorf("Expected 'name' parameter to be required")
	}

	// Check that 'namespace' parameter exists and is optional
	_, namespaceExists := tool.Tool.InputSchema.Properties["namespace"]
	if !namespaceExists {
		t.Errorf("Expected 'namespace' parameter to exist")
	}
}
