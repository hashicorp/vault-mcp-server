// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"testing"
)

func TestGetEnv(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		fallback string
		expected string
	}{
		{
			name:     "returns fallback when env var not set",
			key:      "NON_EXISTENT_VAR",
			fallback: "default_value",
			expected: "default_value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetEnv(tt.key, tt.fallback)
			if result != tt.expected {
				t.Errorf("GetEnv() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestNewVaultClient(t *testing.T) {
	// This is a basic test that checks if the function doesn't panic
	// In a real scenario, you'd want to mock the Vault API
	sessionID := "test-session"
	vaultAddress := "http://127.0.0.1:8200"
	vaultToken := "test-token"

	client, err := NewVaultClient(sessionID, vaultAddress, vaultToken)
	if err != nil {
		t.Logf("NewVaultClient() error = %v (expected in test environment)", err)
	}

	if client != nil {
		// Clean up
		DeleteVaultClient(sessionID)
	}
}
