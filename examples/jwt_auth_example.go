package examples

// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

import (
	"fmt"
	"os"

	"github.com/hashicorp/vault-mcp-server/pkg/auth"
	log "github.com/sirupsen/logrus"
)

// Example: Programmatic JWT authentication with Vault
func main() {
	logger := log.New()
	logger.SetOutput(os.Stdout)
	logger.SetLevel(log.InfoLevel)

	// Example 1: Using environment variables
	fmt.Println("=== Example 1: JWT Authentication from Environment ===")
	fmt.Println()

	// Set environment variables
	os.Setenv("VAULT_ADDR", "http://127.0.0.1:8200")
	os.Setenv("VAULT_JWT_TOKEN", "your-jwt-token-here")
	os.Setenv("VAULT_JWT_ROLE", "mcp-role")
	os.Setenv("VAULT_JWT_AUTH_PATH", "oidc")

	client1, err := auth.AuthenticateWithJWTFromEnv(logger)
	if err != nil {
		logger.Errorf("Authentication failed: %v", err)
	} else {
		logger.Info("Successfully authenticated!")

		// Use the client
		secret, err := client1.Logical().List("secret/metadata")
		if err != nil {
			logger.Errorf("Failed to list secrets: %v", err)
		} else {
			logger.Infof("Secrets: %v", secret.Data)
		}
	}

	fmt.Println()
	fmt.Println("=== Example 2: JWT Authentication with Explicit Config ===")
	fmt.Println()

	// Example 2: Using explicit configuration
	config := auth.VaultJWTConfig{
		Enabled:  true,
		Role:     "mcp-role",
		AuthPath: "oidc",
		JWTToken: "your-jwt-token-here",
	}

	client2, err := auth.AuthenticateWithJWT("http://127.0.0.1:8200", config, logger)
	if err != nil {
		logger.Errorf("Authentication failed: %v", err)
	} else {
		logger.Info("Successfully authenticated!")

		// Get token info
		tokenInfo, err := auth.GetJWTTokenInfo(client2, logger)
		if err != nil {
			logger.Errorf("Failed to get token info: %v", err)
		} else {
			logger.Infof("Token policies: %v", tokenInfo.Data["policies"])
			logger.Infof("Token TTL: %v", tokenInfo.Data["ttl"])
		}
	}

	fmt.Println()
	fmt.Println("=== Example 3: Token Refresh ===")
	fmt.Println()

	// Example 3: Refresh token if renewable
	if client2 != nil {
		err := auth.RefreshVaultToken(client2, logger)
		if err != nil {
			logger.Errorf("Failed to refresh token: %v", err)
		} else {
			logger.Info("Token refreshed successfully")
		}
	}

	fmt.Println()
	fmt.Println("=== Complete! ===")
	fmt.Println()
	fmt.Println("To run this example with a real JWT token:")
	fmt.Println("1. Obtain a JWT token from your OIDC provider (Okta, Auth0, etc.)")
	fmt.Println("2. Set VAULT_JWT_TOKEN environment variable")
	fmt.Println("3. Ensure Vault is configured with OIDC/JWT auth method")
	fmt.Println("4. Run: go run examples/jwt_auth_example.go")
}
