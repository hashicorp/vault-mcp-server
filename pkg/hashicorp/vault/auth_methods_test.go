// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"os"
	"testing"

	log "github.com/sirupsen/logrus"
)

func TestListAuthMethods(t *testing.T) {
	logger := log.New()
	logger.SetOutput(os.Stdout)
	tool := ListAuthMethods(logger)
	
	// Verify tool structure
	if tool.Tool.Name != "list_auth_methods" {
		t.Errorf("Expected tool name 'list_auth_methods', got %s", tool.Tool.Name)
	}
	
	if tool.Tool.Description == "" {
		t.Errorf("Expected non-empty description")
	}
	
	if tool.Handler == nil {
		t.Errorf("Expected non-nil handler")
	}
}

func TestEnableAuthMethod(t *testing.T) {
	logger := log.New()
	logger.SetOutput(os.Stdout)
	tool := EnableAuthMethod(logger)
	
	// Verify tool structure
	if tool.Tool.Name != "enable_auth_method" {
		t.Errorf("Expected tool name 'enable_auth_method', got %s", tool.Tool.Name)
	}
	
	if tool.Tool.Description == "" {
		t.Errorf("Expected non-empty description")
	}
	
	if tool.Handler == nil {
		t.Errorf("Expected non-nil handler")
	}
	
	// Verify required parameters
	pathParam := findParameter(tool.Tool.InputSchema.Properties, "path")
	if pathParam == nil {
		t.Errorf("Expected 'path' parameter")
	}
	
	typeParam := findParameter(tool.Tool.InputSchema.Properties, "type")
	if typeParam == nil {
		t.Errorf("Expected 'type' parameter")
	}
}

func TestDisableAuthMethod(t *testing.T) {
	logger := log.New()
	logger.SetOutput(os.Stdout)
	tool := DisableAuthMethod(logger)
	
	// Verify tool structure
	if tool.Tool.Name != "disable_auth_method" {
		t.Errorf("Expected tool name 'disable_auth_method', got %s", tool.Tool.Name)
	}
	
	if tool.Tool.Description == "" {
		t.Errorf("Expected non-empty description")
	}
	
	if tool.Handler == nil {
		t.Errorf("Expected non-nil handler")
	}
}

func TestReadAuthMethod(t *testing.T) {
	logger := log.New()
	logger.SetOutput(os.Stdout)
	tool := ReadAuthMethod(logger)
	
	// Verify tool structure
	if tool.Tool.Name != "read_auth_method" {
		t.Errorf("Expected tool name 'read_auth_method', got %s", tool.Tool.Name)
	}
	
	if tool.Tool.Description == "" {
		t.Errorf("Expected non-empty description")
	}
	
	if tool.Handler == nil {
		t.Errorf("Expected non-nil handler")
	}
}

// Helper function to find a parameter in tool schema properties
func findParameter(properties map[string]interface{}, paramName string) interface{} {
	if properties == nil {
		return nil
	}
	return properties[paramName]
}
