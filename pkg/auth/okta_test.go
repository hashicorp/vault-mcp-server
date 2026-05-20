// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package auth

import (
	"testing"

	log "github.com/sirupsen/logrus"
)

func TestLoadOktaConfigFromEnv(t *testing.T) {
	tests := []struct {
		name     string
		envVars  map[string]string
		expected OAuthConfig
	}{
		{
			name: "okta enabled with all settings",
			envVars: map[string]string{
				"MCP_AUTH_ENABLED":     "true",
				"OKTA_DOMAIN":          "dev-12345.okta.com",
				"OKTA_AUDIENCE":        "api://default",
				"OKTA_ISSUER":          "https://dev-12345.okta.com/oauth2/default",
				"OKTA_AUTH_SERVER_ID":  "default",
				"OKTA_REQUIRED_SCOPES": "mcp:tools,mcp:resources",
			},
			expected: OAuthConfig{
				Provider:       ProviderOkta,
				Domain:         "dev-12345.okta.com",
				Audience:       "api://default",
				RequiredScopes: []string{"mcp:tools", "mcp:resources"},
				Issuer:         "https://dev-12345.okta.com/oauth2/default",
				AuthServerID:   "default",
				Enabled:        true,
			},
		},
		{
			name: "okta enabled with default auth server",
			envVars: map[string]string{
				"MCP_AUTH_ENABLED": "true",
				"OKTA_DOMAIN":      "dev-12345.okta.com",
				"OKTA_AUDIENCE":    "api://default",
			},
			expected: OAuthConfig{
				Provider:       ProviderOkta,
				Domain:         "dev-12345.okta.com",
				Audience:       "api://default",
				RequiredScopes: []string{"mcp:tools", "mcp:resources"},
				Issuer:         "",
				AuthServerID:   "default",
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

			config := LoadOktaConfigFromEnv()

			if config.Enabled != tt.expected.Enabled {
				t.Errorf("Expected Enabled=%v, got %v", tt.expected.Enabled, config.Enabled)
			}
			if config.Provider != tt.expected.Provider {
				t.Errorf("Expected Provider=%v, got %v", tt.expected.Provider, config.Provider)
			}
			if config.Domain != tt.expected.Domain {
				t.Errorf("Expected Domain=%s, got %s", tt.expected.Domain, config.Domain)
			}
			if config.Audience != tt.expected.Audience {
				t.Errorf("Expected Audience=%s, got %s", tt.expected.Audience, config.Audience)
			}
			if config.AuthServerID != tt.expected.AuthServerID {
				t.Errorf("Expected AuthServerID=%s, got %s", tt.expected.AuthServerID, config.AuthServerID)
			}
		})
	}
}

func TestLoadOAuthConfigFromEnv(t *testing.T) {
	tests := []struct {
		name             string
		envVars          map[string]string
		expectedProvider ProviderType
	}{
		{
			name: "auto-detect okta",
			envVars: map[string]string{
				"MCP_AUTH_ENABLED": "true",
				"OKTA_DOMAIN":      "dev-12345.okta.com",
				"OKTA_AUDIENCE":    "api://default",
			},
			expectedProvider: ProviderOkta,
		},
		{
			name: "auto-detect auth0",
			envVars: map[string]string{
				"MCP_AUTH_ENABLED": "true",
				"AUTH0_DOMAIN":     "test.auth0.com",
				"AUTH0_AUDIENCE":   "https://api.test.com",
			},
			expectedProvider: ProviderAuth0,
		},
		{
			name: "explicit okta provider",
			envVars: map[string]string{
				"MCP_AUTH_ENABLED":  "true",
				"MCP_AUTH_PROVIDER": "okta",
				"OKTA_DOMAIN":       "dev-12345.okta.com",
				"OKTA_AUDIENCE":     "api://default",
			},
			expectedProvider: ProviderOkta,
		},
		{
			name: "explicit auth0 provider",
			envVars: map[string]string{
				"MCP_AUTH_ENABLED":  "true",
				"MCP_AUTH_PROVIDER": "auth0",
				"AUTH0_DOMAIN":      "test.auth0.com",
				"AUTH0_AUDIENCE":    "https://api.test.com",
			},
			expectedProvider: ProviderAuth0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variables
			for key, value := range tt.envVars {
				t.Setenv(key, value)
			}

			config := LoadOAuthConfigFromEnv()

			if config.Provider != tt.expectedProvider {
				t.Errorf("Expected Provider=%v, got %v", tt.expectedProvider, config.Provider)
			}
		})
	}
}

func TestValidateOktaConfig(t *testing.T) {
	logger := log.New()
	logger.SetLevel(log.ErrorLevel)

	tests := []struct {
		name      string
		config    OAuthConfig
		expectErr bool
	}{
		{
			name: "valid okta config",
			config: OAuthConfig{
				Provider:     ProviderOkta,
				Enabled:      true,
				Domain:       "dev-12345.okta.com",
				Audience:     "api://default",
				AuthServerID: "default",
			},
			expectErr: false,
		},
		{
			name: "missing okta domain",
			config: OAuthConfig{
				Provider: ProviderOkta,
				Enabled:  true,
				Audience: "api://default",
			},
			expectErr: true,
		},
		{
			name: "missing okta audience",
			config: OAuthConfig{
				Provider: ProviderOkta,
				Enabled:  true,
				Domain:   "dev-12345.okta.com",
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateOktaConfig(tt.config, logger)
			if (err != nil) != tt.expectErr {
				t.Errorf("Expected error=%v, got %v", tt.expectErr, err)
			}
		})
	}
}

func TestNewOAuthValidator_Okta(t *testing.T) {
	logger := log.New()
	logger.SetLevel(log.ErrorLevel)

	tests := []struct {
		name            string
		config          OAuthConfig
		expectedJWKSURL string
		expectedIssuer  string
	}{
		{
			name: "okta with default auth server",
			config: OAuthConfig{
				Provider:     ProviderOkta,
				Domain:       "dev-12345.okta.com",
				Audience:     "api://default",
				AuthServerID: "default",
			},
			expectedJWKSURL: "https://dev-12345.okta.com/oauth2/default/v1/keys",
			expectedIssuer:  "https://dev-12345.okta.com/oauth2/default",
		},
		{
			name: "okta with custom auth server",
			config: OAuthConfig{
				Provider:     ProviderOkta,
				Domain:       "dev-12345.okta.com",
				Audience:     "api://custom",
				AuthServerID: "custom",
			},
			expectedJWKSURL: "https://dev-12345.okta.com/oauth2/custom/v1/keys",
			expectedIssuer:  "https://dev-12345.okta.com/oauth2/custom",
		},
		{
			name: "auth0 config",
			config: OAuthConfig{
				Provider: ProviderAuth0,
				Domain:   "test.auth0.com",
				Audience: "https://api.test.com",
			},
			expectedJWKSURL: "https://test.auth0.com/.well-known/jwks.json",
			expectedIssuer:  "https://test.auth0.com/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator := NewOAuthValidator(tt.config, logger)

			if validator.jwksURL != tt.expectedJWKSURL {
				t.Errorf("Expected JWKS URL=%s, got %s", tt.expectedJWKSURL, validator.jwksURL)
			}

			if validator.config.Issuer != tt.expectedIssuer {
				t.Errorf("Expected Issuer=%s, got %s", tt.expectedIssuer, validator.config.Issuer)
			}
		})
	}
}
