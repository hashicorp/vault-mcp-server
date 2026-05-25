// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault-mcp-server/pkg/auth"
	log "github.com/sirupsen/logrus"
)

// AuthManagerGetter is a function that returns the current AuthManager
type AuthManagerGetter func() auth.AuthManager

var (
	// Global AuthManager getter
	authManagerGetter AuthManagerGetter
)

// SetAuthManagerGetter sets the function to retrieve the AuthManager
func SetAuthManagerGetter(getter AuthManagerGetter) {
	authManagerGetter = getter
}

// GetAuthManager returns the current AuthManager if set
func GetAuthManager() auth.AuthManager {
	if authManagerGetter == nil {
		return nil
	}
	return authManagerGetter()
}

// GetVaultTokenFromAuthManager attempts to get a Vault token from the AuthManager
func GetVaultTokenFromAuthManager(ctx context.Context, logger *log.Logger) (string, error) {
	authManager := GetAuthManager()
	if authManager == nil {
		return "", fmt.Errorf("AuthManager not available")
	}

	if !authManager.IsAuthenticated() {
		logger.Info("Not authenticated, triggering OIDC flow")
	}

	token, err := authManager.GetOrAuthenticateVaultToken(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get Vault token from AuthManager: %w", err)
	}

	return token, nil
}
