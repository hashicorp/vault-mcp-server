// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package auth

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
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

// OIDCConfig holds OIDC authentication configuration
type OIDCConfig struct {
	// Core OIDC settings
	Issuer       string   `yaml:"issuer" json:"issuer"`                         // OIDC issuer URL (e.g., https://accounts.google.com)
	ClientID     string   `yaml:"client_id" json:"client_id"`                   // OAuth 2.0 client ID
	ClientSecret string   `yaml:"client_secret" json:"client_secret,omitempty"` // Optional client secret (for confidential clients)
	RedirectURI  string   `yaml:"redirect_uri" json:"redirect_uri"`             // OAuth callback URL (e.g., http://localhost:8765/callback)
	Audience     string   `yaml:"audience" json:"audience,omitempty"`           // Token audience (must match Vault bound_audiences)
	Scopes       []string `yaml:"scopes" json:"scopes"`                         // Requested scopes (e.g., openid, profile, email)

	// Flow settings
	AuthTimeout         time.Duration `yaml:"auth_timeout" json:"auth_timeout"`                   // Timeout for auth flow (default: 120s)
	RequestRefreshToken bool          `yaml:"request_refresh_token" json:"request_refresh_token"` // Request refresh token (offline_access scope)

	// Token refresh settings
	RefreshThreshold time.Duration `yaml:"refresh_threshold" json:"refresh_threshold"` // Refresh when token expires within this duration (default: 5m)

	// Vault integration
	VaultTokenSource string `yaml:"vault_token_source" json:"vault_token_source"` // Token source: oidc, static, or auto (default: auto)

	// Enabled flag
	Enabled bool `yaml:"enabled" json:"enabled"`
}

// Config represents the complete configuration (file + env vars)
type Config struct {
	OIDC  OIDCConfig  `yaml:"oidc" json:"oidc"`
	OAuth OAuthConfig `yaml:"oauth" json:"oauth"` // Existing OAuth validator config
}

// DefaultOIDCConfig returns OIDC configuration with default values
func DefaultOIDCConfig() OIDCConfig {
	return OIDCConfig{
		RedirectURI:         "http://localhost:8765/callback",
		Scopes:              []string{"openid", "profile", "email"},
		AuthTimeout:         120 * time.Second,
		RequestRefreshToken: true,
		RefreshThreshold:    5 * time.Minute,
		VaultTokenSource:    "auto",
		Enabled:             false,
	}
}

// LoadOIDCConfigFromEnv loads OIDC configuration from environment variables
func LoadOIDCConfigFromEnv() OIDCConfig {
	config := DefaultOIDCConfig()

	if issuer := os.Getenv("OIDC_ISSUER"); issuer != "" {
		config.Issuer = issuer
	}

	if clientID := os.Getenv("OIDC_CLIENT_ID"); clientID != "" {
		config.ClientID = clientID
	}

	if clientSecret := os.Getenv("OIDC_CLIENT_SECRET"); clientSecret != "" {
		config.ClientSecret = clientSecret
	}

	if redirectURI := os.Getenv("OIDC_REDIRECT_URI"); redirectURI != "" {
		config.RedirectURI = redirectURI
	}

	if scopes := os.Getenv("OIDC_SCOPES"); scopes != "" {
		config.Scopes = strings.Split(scopes, ",")
		// Trim whitespace from each scope
		for i, scope := range config.Scopes {
			config.Scopes[i] = strings.TrimSpace(scope)
		}
	}

	if timeoutStr := os.Getenv("OIDC_AUTH_TIMEOUT_SECONDS"); timeoutStr != "" {
		if timeout, err := strconv.Atoi(timeoutStr); err == nil && timeout > 0 {
			config.AuthTimeout = time.Duration(timeout) * time.Second
		}
	}

	if refreshToken := os.Getenv("OIDC_REQUEST_REFRESH_TOKEN"); refreshToken != "" {
		config.RequestRefreshToken = strings.ToLower(refreshToken) == "true"
	}

	if thresholdStr := os.Getenv("OIDC_REFRESH_THRESHOLD_SECONDS"); thresholdStr != "" {
		if threshold, err := strconv.Atoi(thresholdStr); err == nil && threshold > 0 {
			config.RefreshThreshold = time.Duration(threshold) * time.Second
		}
	}

	if tokenSource := os.Getenv("VAULT_TOKEN_SOURCE"); tokenSource != "" {
		config.VaultTokenSource = tokenSource
	}

	// Enable OIDC if issuer and client ID are provided
	if config.Issuer != "" && config.ClientID != "" {
		config.Enabled = true
	}

	return config
}

// LoadConfigFromFile loads configuration from a YAML file
func LoadConfigFromFile(filePath string) (*Config, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return &config, nil
}

// LoadConfig loads configuration from file and environment variables
// Environment variables override file configuration
func LoadConfig(filePath string, logger *log.Logger) (*Config, error) {
	config := &Config{
		OIDC: DefaultOIDCConfig(),
	}

	// Load from file if it exists
	if filePath != "" {
		fileConfig, err := LoadConfigFromFile(filePath)
		if err != nil {
			if !os.IsNotExist(err) {
				return nil, err
			}
			logger.WithField("path", filePath).Debug("Config file not found, using defaults")
		} else {
			config = fileConfig
			logger.WithField("path", filePath).Info("Loaded configuration from file")
		}
	}

	// Override with environment variables
	envOIDC := LoadOIDCConfigFromEnv()
	if envOIDC.Issuer != "" {
		config.OIDC.Issuer = envOIDC.Issuer
	}
	if envOIDC.ClientID != "" {
		config.OIDC.ClientID = envOIDC.ClientID
	}
	if envOIDC.ClientSecret != "" {
		config.OIDC.ClientSecret = envOIDC.ClientSecret
	}
	if envOIDC.RedirectURI != "" && envOIDC.RedirectURI != DefaultOIDCConfig().RedirectURI {
		config.OIDC.RedirectURI = envOIDC.RedirectURI
	}
	if len(envOIDC.Scopes) > 0 && os.Getenv("OIDC_SCOPES") != "" {
		config.OIDC.Scopes = envOIDC.Scopes
	}
	if os.Getenv("OIDC_AUTH_TIMEOUT_SECONDS") != "" {
		config.OIDC.AuthTimeout = envOIDC.AuthTimeout
	}
	if os.Getenv("OIDC_REQUEST_REFRESH_TOKEN") != "" {
		config.OIDC.RequestRefreshToken = envOIDC.RequestRefreshToken
	}
	if os.Getenv("OIDC_REFRESH_THRESHOLD_SECONDS") != "" {
		config.OIDC.RefreshThreshold = envOIDC.RefreshThreshold
	}
	if os.Getenv("VAULT_TOKEN_SOURCE") != "" {
		config.OIDC.VaultTokenSource = envOIDC.VaultTokenSource
	}
	if envOIDC.Enabled {
		config.OIDC.Enabled = true
	}

	return config, nil
}

// ValidateOIDCConfig validates the OIDC configuration
func ValidateOIDCConfig(config OIDCConfig, logger *log.Logger) error {
	if !config.Enabled {
		logger.Info("OIDC authentication is disabled")
		return nil
	}

	if config.Issuer == "" {
		return fmt.Errorf("OIDC issuer is required when OIDC authentication is enabled")
	}

	if config.ClientID == "" {
		return fmt.Errorf("OIDC client ID is required when OIDC authentication is enabled")
	}

	if config.RedirectURI == "" {
		return fmt.Errorf("OIDC redirect URI is required when OIDC authentication is enabled")
	}

	if len(config.Scopes) == 0 {
		return fmt.Errorf("OIDC scopes are required when OIDC authentication is enabled")
	}

	// Validate that openid scope is present
	hasOpenID := false
	for _, scope := range config.Scopes {
		if scope == "openid" {
			hasOpenID = true
			break
		}
	}
	if !hasOpenID {
		logger.Warn("OIDC scopes do not include 'openid', adding it automatically")
		config.Scopes = append([]string{"openid"}, config.Scopes...)
	}

	// Add offline_access scope if refresh token requested
	if config.RequestRefreshToken {
		hasOfflineAccess := false
		for _, scope := range config.Scopes {
			if scope == "offline_access" {
				hasOfflineAccess = true
				break
			}
		}
		if !hasOfflineAccess {
			logger.Debug("Adding 'offline_access' scope for refresh token support")
			config.Scopes = append(config.Scopes, "offline_access")
		}
	}

	logger.Info("OIDC authentication enabled")
	logger.WithFields(log.Fields{
		"issuer":       config.Issuer,
		"client_id":    config.ClientID,
		"redirect_uri": config.RedirectURI,
		"audience":     config.Audience,
		"scopes":       strings.Join(config.Scopes, ", "),
		"auth_timeout": config.AuthTimeout,
	}).Debug("OIDC configuration")

	return nil
}
