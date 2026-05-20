// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package auth

import (
	"fmt"
	"os"

	"github.com/hashicorp/vault/api"
	log "github.com/sirupsen/logrus"
)

// VaultJWTConfig holds configuration for Vault JWT authentication
type VaultJWTConfig struct {
	Enabled    bool   // Whether JWT auth is enabled
	Role       string // Vault JWT role name
	AuthPath   string // Vault auth path (default: "oidc")
	JWTToken   string // JWT token for authentication
}

// LoadVaultJWTConfigFromEnv loads Vault JWT configuration from environment variables
func LoadVaultJWTConfigFromEnv() VaultJWTConfig {
	return VaultJWTConfig{
		Enabled:  os.Getenv("VAULT_JWT_AUTH_ENABLED") == "true",
		Role:     getEnvOrDefault("VAULT_JWT_ROLE", "mcp-role"),
		AuthPath: getEnvOrDefault("VAULT_JWT_AUTH_PATH", "oidc"),
		JWTToken: os.Getenv("VAULT_JWT_TOKEN"),
	}
}

// getEnvOrDefault gets environment variable or returns default value
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// AuthenticateWithJWT authenticates to Vault using a JWT token and returns a Vault client
func AuthenticateWithJWT(vaultAddr string, config VaultJWTConfig, logger *log.Logger) (*api.Client, error) {
	if !config.Enabled {
		return nil, fmt.Errorf("JWT authentication is not enabled")
	}

	if config.JWTToken == "" {
		return nil, fmt.Errorf("JWT token is required but not provided")
	}

	// Create Vault client
	clientConfig := api.DefaultConfig()
	clientConfig.Address = vaultAddr

	client, err := api.NewClient(clientConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create Vault client: %w", err)
	}

	logger.WithFields(log.Fields{
		"vault_addr": vaultAddr,
		"auth_path":  config.AuthPath,
		"role":       config.Role,
	}).Info("Attempting JWT authentication with Vault")

	// Prepare authentication data
	data := map[string]interface{}{
		"role": config.Role,
		"jwt":  config.JWTToken,
	}

	// Authenticate using JWT
	authPath := fmt.Sprintf("auth/%s/login", config.AuthPath)
	secret, err := client.Logical().Write(authPath, data)
	if err != nil {
		return nil, fmt.Errorf("JWT authentication failed: %w", err)
	}

	if secret == nil || secret.Auth == nil {
		return nil, fmt.Errorf("no authentication data returned from Vault")
	}

	// Set the Vault token
	vaultToken := secret.Auth.ClientToken
	client.SetToken(vaultToken)

	logger.WithFields(log.Fields{
		"token_ttl":       secret.Auth.LeaseDuration,
		"token_renewable": secret.Auth.Renewable,
		"policies":        secret.Auth.Policies,
	}).Info("Successfully authenticated to Vault using JWT")

	return client, nil
}

// AuthenticateWithJWTFromEnv authenticates to Vault using JWT token from environment variables
func AuthenticateWithJWTFromEnv(logger *log.Logger) (*api.Client, error) {
	vaultAddr := os.Getenv("VAULT_ADDR")
	if vaultAddr == "" {
		vaultAddr = "http://127.0.0.1:8200"
	}

	config := LoadVaultJWTConfigFromEnv()
	return AuthenticateWithJWT(vaultAddr, config, logger)
}

// RefreshVaultToken refreshes the Vault token if it's renewable
func RefreshVaultToken(client *api.Client, logger *log.Logger) error {
	secret, err := client.Auth().Token().RenewSelf(0)
	if err != nil {
		return fmt.Errorf("failed to renew token: %w", err)
	}

	if secret == nil || secret.Auth == nil {
		return fmt.Errorf("no token data returned from renewal")
	}

	logger.WithFields(log.Fields{
		"token_ttl":       secret.Auth.LeaseDuration,
		"token_renewable": secret.Auth.Renewable,
	}).Info("Successfully renewed Vault token")

	return nil
}

// GetJWTTokenInfo validates and extracts information from a JWT token
func GetJWTTokenInfo(client *api.Client, logger *log.Logger) (*api.Secret, error) {
	secret, err := client.Auth().Token().LookupSelf()
	if err != nil {
		return nil, fmt.Errorf("failed to lookup token: %w", err)
	}

	logger.WithFields(log.Fields{
		"policies": secret.Data["policies"],
		"ttl":      secret.Data["ttl"],
	}).Debug("Token information retrieved")

	return secret, nil
}
