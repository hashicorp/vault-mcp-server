// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package auth

import (
	"fmt"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
)

// ValidateAuth0Config validates the Auth0 configuration
func ValidateAuth0Config(config Auth0Config, logger *log.Logger) error {
	return ValidateOAuthConfig(config, logger)
}

// ValidateOktaConfig validates the Okta configuration
func ValidateOktaConfig(config OAuthConfig, logger *log.Logger) error {
	return ValidateOAuthConfig(config, logger)
}

// ValidateOAuthConfig validates the OAuth configuration
func ValidateOAuthConfig(config OAuthConfig, logger *log.Logger) error {
	if !config.Enabled {
		logger.Info("Authentication is disabled")
		return nil
	}

	providerName := string(config.Provider)
	if providerName == "" {
		providerName = "OAuth"
	}

	if config.Domain == "" {
		return fmt.Errorf("%s domain is required when authentication is enabled", providerName)
	}

	if config.Audience == "" {
		return fmt.Errorf("%s audience is required when authentication is enabled", providerName)
	}

	logger.Infof("Authentication enabled with %s", providerName)
	logger.Infof("%s Domain: %s", providerName, config.Domain)
	logger.Infof("%s Audience: %s", providerName, config.Audience)

	if config.Provider == ProviderOkta && config.AuthServerID != "" {
		logger.Infof("Okta Auth Server ID: %s", config.AuthServerID)
	}

	logger.Infof("Required Scopes: %s", strings.Join(config.RequiredScopes, ", "))

	return nil
}

// GetServerBaseURL constructs the base URL for the server
func GetServerBaseURL(host, port string, useTLS bool) string {
	scheme := "http"
	if useTLS {
		scheme = "https"
	}

	// Handle standard ports
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		return fmt.Sprintf("%s://%s", scheme, host)
	}

	return fmt.Sprintf("%s://%s:%s", scheme, host, port)
}

// GetResourceMetadataURL constructs the Protected Resource Metadata URL
func GetResourceMetadataURL(baseURL string) string {
	return baseURL + "/.well-known/oauth-protected-resource"
}

// IsAuthEnabled checks if authentication should be enabled
func IsAuthEnabled() bool {
	return os.Getenv("MCP_AUTH_ENABLED") == "true"
}
