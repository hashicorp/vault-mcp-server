// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package auth

import (
	"os"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestLoadVaultJWTConfigFromEnv(t *testing.T) {
	tests := []struct {
		name     string
		envVars  map[string]string
		expected VaultJWTConfig
	}{
		{
			name: "all environment variables set",
			envVars: map[string]string{
				"VAULT_JWT_AUTH_ENABLED": "true",
				"VAULT_JWT_ROLE":         "test-role",
				"VAULT_JWT_AUTH_PATH":    "jwt",
				"VAULT_JWT_TOKEN":        "test-token",
			},
			expected: VaultJWTConfig{
				Enabled:  true,
				Role:     "test-role",
				AuthPath: "jwt",
				JWTToken: "test-token",
			},
		},
		{
			name: "default values used",
			envVars: map[string]string{
				"VAULT_JWT_AUTH_ENABLED": "true",
			},
			expected: VaultJWTConfig{
				Enabled:  true,
				Role:     "mcp-role",
				AuthPath: "oidc",
				JWTToken: "",
			},
		},
		{
			name:    "disabled by default",
			envVars: map[string]string{},
			expected: VaultJWTConfig{
				Enabled:  false,
				Role:     "mcp-role",
				AuthPath: "oidc",
				JWTToken: "",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear environment
			os.Clearenv()

			// Set environment variables
			for k, v := range tt.envVars {
				os.Setenv(k, v)
			}

			config := LoadVaultJWTConfigFromEnv()

			assert.Equal(t, tt.expected.Enabled, config.Enabled)
			assert.Equal(t, tt.expected.Role, config.Role)
			assert.Equal(t, tt.expected.AuthPath, config.AuthPath)
			assert.Equal(t, tt.expected.JWTToken, config.JWTToken)
		})
	}
}

func TestAuthenticateWithJWT_Disabled(t *testing.T) {
	logger := log.New()
	logger.SetOutput(os.Stdout)

	config := VaultJWTConfig{
		Enabled: false,
	}

	_, err := AuthenticateWithJWT("http://127.0.0.1:8200", config, logger)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "JWT authentication is not enabled")
}

func TestAuthenticateWithJWT_MissingToken(t *testing.T) {
	logger := log.New()
	logger.SetOutput(os.Stdout)

	config := VaultJWTConfig{
		Enabled:  true,
		Role:     "test-role",
		AuthPath: "oidc",
		JWTToken: "",
	}

	_, err := AuthenticateWithJWT("http://127.0.0.1:8200", config, logger)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "JWT token is required")
}

func TestGetEnvOrDefault(t *testing.T) {
	tests := []struct {
		name         string
		envKey       string
		envValue     string
		defaultValue string
		expected     string
	}{
		{
			name:         "environment variable set",
			envKey:       "TEST_KEY",
			envValue:     "test-value",
			defaultValue: "default-value",
			expected:     "test-value",
		},
		{
			name:         "environment variable not set",
			envKey:       "TEST_KEY_NOT_SET",
			envValue:     "",
			defaultValue: "default-value",
			expected:     "default-value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Clearenv()
			if tt.envValue != "" {
				os.Setenv(tt.envKey, tt.envValue)
			}

			result := getEnvOrDefault(tt.envKey, tt.defaultValue)
			assert.Equal(t, tt.expected, result)
		})
	}
}
