// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package auth

import (
	"testing"

	log "github.com/sirupsen/logrus"
)

func TestLoadAuth0ConfigFromEnv(t *testing.T) {
	tests := []struct {
		name     string
		envVars  map[string]string
		expected Auth0Config
	}{
		{
			name: "auth disabled",
			envVars: map[string]string{
				"MCP_AUTH_ENABLED": "false",
			},
			expected: Auth0Config{
				Enabled: false,
			},
		},
		{
			name: "auth enabled with all settings",
			envVars: map[string]string{
				"MCP_AUTH_ENABLED":      "true",
				"AUTH0_DOMAIN":          "test.auth0.com",
				"AUTH0_AUDIENCE":        "https://api.test.com",
				"AUTH0_ISSUER":          "https://test.auth0.com/",
				"AUTH0_REQUIRED_SCOPES": "mcp:tools,mcp:resources",
			},
			expected: Auth0Config{
				Domain:         "test.auth0.com",
				Audience:       "https://api.test.com",
				RequiredScopes: []string{"mcp:tools", "mcp:resources"},
				Issuer:         "https://test.auth0.com/",
				Enabled:        true,
			},
		},
		{
			name: "auth enabled with default scopes",
			envVars: map[string]string{
				"MCP_AUTH_ENABLED": "true",
				"AUTH0_DOMAIN":     "test.auth0.com",
				"AUTH0_AUDIENCE":   "https://api.test.com",
			},
			expected: Auth0Config{
				Domain:         "test.auth0.com",
				Audience:       "https://api.test.com",
				RequiredScopes: []string{"mcp:tools", "mcp:resources"},
				Issuer:         "",
				Enabled:        true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variables
			for key, value := range tt.envVars {
				t.Setenv(key, value)
			}

			config := LoadAuth0ConfigFromEnv()

			if config.Enabled != tt.expected.Enabled {
				t.Errorf("Expected Enabled=%v, got %v", tt.expected.Enabled, config.Enabled)
			}
			if config.Domain != tt.expected.Domain {
				t.Errorf("Expected Domain=%s, got %s", tt.expected.Domain, config.Domain)
			}
			if config.Audience != tt.expected.Audience {
				t.Errorf("Expected Audience=%s, got %s", tt.expected.Audience, config.Audience)
			}
			if config.Issuer != tt.expected.Issuer {
				t.Errorf("Expected Issuer=%s, got %s", tt.expected.Issuer, config.Issuer)
			}
		})
	}
}

func TestValidateAuth0Config(t *testing.T) {
	logger := log.New()
	logger.SetLevel(log.ErrorLevel)

	tests := []struct {
		name      string
		config    Auth0Config
		expectErr bool
	}{
		{
			name: "valid config",
			config: Auth0Config{
				Enabled:  true,
				Domain:   "test.auth0.com",
				Audience: "https://api.test.com",
			},
			expectErr: false,
		},
		{
			name: "auth disabled",
			config: Auth0Config{
				Enabled: false,
			},
			expectErr: false,
		},
		{
			name: "missing domain",
			config: Auth0Config{
				Enabled:  true,
				Audience: "https://api.test.com",
			},
			expectErr: true,
		},
		{
			name: "missing audience",
			config: Auth0Config{
				Enabled: true,
				Domain:  "test.auth0.com",
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAuth0Config(tt.config, logger)
			if (err != nil) != tt.expectErr {
				t.Errorf("Expected error=%v, got %v", tt.expectErr, err)
			}
		})
	}
}

func TestGetServerBaseURL(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		port     string
		useTLS   bool
		expected string
	}{
		{
			name:     "http with custom port",
			host:     "localhost",
			port:     "8080",
			useTLS:   false,
			expected: "http://localhost:8080",
		},
		{
			name:     "https with custom port",
			host:     "example.com",
			port:     "8443",
			useTLS:   true,
			expected: "https://example.com:8443",
		},
		{
			name:     "http with standard port",
			host:     "example.com",
			port:     "80",
			useTLS:   false,
			expected: "http://example.com",
		},
		{
			name:     "https with standard port",
			host:     "example.com",
			port:     "443",
			useTLS:   true,
			expected: "https://example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetServerBaseURL(tt.host, tt.port, tt.useTLS)
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestGetResourceMetadataURL(t *testing.T) {
	tests := []struct {
		name     string
		baseURL  string
		expected string
	}{
		{
			name:     "basic url",
			baseURL:  "http://localhost:8080",
			expected: "http://localhost:8080/.well-known/oauth-protected-resource",
		},
		{
			name:     "url with path",
			baseURL:  "https://api.example.com/v1",
			expected: "https://api.example.com/v1/.well-known/oauth-protected-resource",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetResourceMetadataURL(tt.baseURL)
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestWWWAuthenticateHeader(t *testing.T) {
	tests := []struct {
		name                string
		realm               string
		resourceMetadataURL string
		scopes              []string
		expected            string
	}{
		{
			name:                "with all parameters",
			realm:               "mcp",
			resourceMetadataURL: "http://localhost:8080/.well-known/oauth-protected-resource",
			scopes:              []string{"mcp:tools", "mcp:resources"},
			expected:            `Bearer realm="mcp", resource_metadata="http://localhost:8080/.well-known/oauth-protected-resource", scope="mcp:tools mcp:resources"`,
		},
		{
			name:                "without scopes",
			realm:               "api",
			resourceMetadataURL: "http://localhost:8080/.well-known/oauth-protected-resource",
			scopes:              []string{},
			expected:            `Bearer realm="api", resource_metadata="http://localhost:8080/.well-known/oauth-protected-resource"`,
		},
		{
			name:     "minimal",
			realm:    "test",
			expected: `Bearer realm="test"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := WWWAuthenticateHeader(tt.realm, tt.resourceMetadataURL, tt.scopes)
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}
