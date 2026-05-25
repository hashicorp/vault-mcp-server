// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// AuthStatus represents the current authentication status
type AuthStatus struct {
	Authenticated     bool      `json:"authenticated"`
	UserID            string    `json:"user_id,omitempty"`
	TokenExpiry       time.Time `json:"token_expiry,omitempty"`
	VaultToken        string    `json:"-"` // Don't expose in JSON
	VaultTokenExpiry  time.Time `json:"vault_token_expiry,omitempty"`
	LastAuthenticated time.Time `json:"last_authenticated,omitempty"`
	RequiresRefresh   bool      `json:"requires_refresh"`
	RequiresReauth    bool      `json:"requires_reauth"`
}

// AuthManager manages OIDC authentication and token lifecycle
type AuthManager interface {
	// GetOrAuthenticateVaultToken returns a valid Vault token, triggering auth if necessary
	GetOrAuthenticateVaultToken(ctx context.Context) (string, error)

	// IsAuthenticated checks if there is a valid authentication session
	IsAuthenticated() bool

	// GetAuthStatus returns the current authentication status
	GetAuthStatus() *AuthStatus

	// RefreshIfNeeded checks if tokens need refresh and refreshes them if necessary
	RefreshIfNeeded(ctx context.Context) error

	// ClearAuth clears all cached authentication state
	ClearAuth() error
}

// DefaultAuthManager is the default implementation of AuthManager
type DefaultAuthManager struct {
	config         OIDCConfig
	oidcClient     *OIDCClient
	validator      *TokenValidator
	vaultJWTConfig VaultJWTConfig
	cache          *TokenCache
	cacheMu        sync.RWMutex
	refreshMu      sync.Mutex // Serializes refresh attempts
	logger         *log.Logger
}

// NewAuthManager creates a new authentication manager
func NewAuthManager(config OIDCConfig, vaultJWTConfig VaultJWTConfig, logger *log.Logger) (AuthManager, error) {
	if !config.Enabled {
		logger.Info("OIDC authentication is disabled")
		return &DefaultAuthManager{
			config: config,
			logger: logger,
		}, nil
	}

	// Validate OIDC config
	if err := ValidateOIDCConfig(config, logger); err != nil {
		return nil, fmt.Errorf("invalid OIDC config: %w", err)
	}

	// Create OIDC client
	oidcClient, err := NewOIDCClient(config, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC client: %w", err)
	}

	// Create token validator
	validator := NewTokenValidator(oidcClient, logger)

	// Load cached tokens if available
	cache, err := LoadCache(logger)
	if err != nil {
		logger.WithError(err).Warn("Failed to load token cache, will require re-authentication")
		cache = nil
	}

	// Validate cache if loaded
	if cache != nil {
		if err := validator.ValidateCache(cache); err != nil {
			logger.WithError(err).Warn("Cached tokens are invalid, will require re-authentication")
			cache = nil
		} else {
			logger.WithField("user_id", cache.UserID).Info("Loaded valid cached tokens")
		}
	}

	manager := &DefaultAuthManager{
		config:         config,
		oidcClient:     oidcClient,
		validator:      validator,
		vaultJWTConfig: vaultJWTConfig,
		cache:          cache,
		logger:         logger,
	}

	return manager, nil
}

// GetOrAuthenticateVaultToken returns a valid Vault token, triggering auth if necessary
func (am *DefaultAuthManager) GetOrAuthenticateVaultToken(ctx context.Context) (string, error) {
	if !am.config.Enabled {
		return "", fmt.Errorf("OIDC authentication is not enabled")
	}

	am.cacheMu.RLock()
	cache := am.cache
	am.cacheMu.RUnlock()

	// Check if we have a valid Vault token
	if cache != nil && cache.VaultToken != "" && !cache.IsVaultTokenExpired() {
		am.logger.Debug("Using cached Vault token")
		return cache.VaultToken, nil
	}

	// Check if we need to refresh tokens
	if cache != nil && cache.RefreshToken != "" && cache.IsExpired() {
		am.logger.Info("Access token expired, attempting silent refresh")
		if err := am.refreshTokens(); err != nil {
			am.logger.WithError(err).Warn("Token refresh failed, will trigger full re-authentication")
			cache = nil
		} else {
			am.cacheMu.RLock()
			cache = am.cache
			am.cacheMu.RUnlock()
		}
	}

	// Check if we have valid OIDC tokens
	if cache == nil || cache.AccessToken == "" || cache.IsExpired() {
		am.logger.Info("No valid tokens found, triggering OIDC authentication")
		if err := am.authenticate(); err != nil {
			return "", fmt.Errorf("authentication failed: %w", err)
		}

		am.cacheMu.RLock()
		cache = am.cache
		am.cacheMu.RUnlock()
	}

	// Authenticate with Vault using access token (has correct audience)
	if cache.VaultToken == "" || cache.IsVaultTokenExpired() {
		am.logger.Info("Authenticating with Vault using OIDC token")
		vaultToken, vaultTokenExpiry, err := am.authenticateVault(cache.AccessToken)
		if err != nil {
			return "", fmt.Errorf("Vault authentication failed: %w", err)
		}

		// Update cache with Vault token
		am.cacheMu.Lock()
		am.cache.VaultToken = vaultToken
		am.cache.VaultTokenExpiresAt = vaultTokenExpiry
		if err := SaveCache(am.cache, am.logger); err != nil {
			am.logger.WithError(err).Warn("Failed to save updated cache")
		}
		am.cacheMu.Unlock()

		return vaultToken, nil
	}

	return cache.VaultToken, nil
}

// IsAuthenticated checks if there is a valid authentication session
func (am *DefaultAuthManager) IsAuthenticated() bool {
	if !am.config.Enabled {
		return false
	}

	am.cacheMu.RLock()
	defer am.cacheMu.RUnlock()

	if am.cache == nil {
		return false
	}

	return am.cache.AccessToken != "" && !am.cache.IsExpired()
}

// GetAuthStatus returns the current authentication status
func (am *DefaultAuthManager) GetAuthStatus() *AuthStatus {
	status := &AuthStatus{
		Authenticated: false,
	}

	if !am.config.Enabled {
		return status
	}

	am.cacheMu.RLock()
	defer am.cacheMu.RUnlock()

	if am.cache == nil {
		status.RequiresReauth = true
		return status
	}

	status.Authenticated = am.cache.AccessToken != "" && !am.cache.IsExpired()
	status.UserID = am.cache.UserID
	status.TokenExpiry = am.cache.ExpiresAt
	status.VaultTokenExpiry = am.cache.VaultTokenExpiresAt
	status.LastAuthenticated = am.cache.CachedAt

	// Check if tokens need refresh
	if am.cache.IsExpired() {
		status.RequiresReauth = true
	} else if am.validator.ShouldRefresh(am.cache.ExpiresAt, am.config.RefreshThreshold) {
		status.RequiresRefresh = true
	}

	return status
}

// RefreshIfNeeded checks if tokens need refresh and refreshes them if necessary
func (am *DefaultAuthManager) RefreshIfNeeded(ctx context.Context) error {
	if !am.config.Enabled {
		return nil
	}

	am.cacheMu.RLock()
	cache := am.cache
	am.cacheMu.RUnlock()

	if cache == nil || cache.RefreshToken == "" {
		return fmt.Errorf("no refresh token available")
	}

	// Check if refresh is needed
	if !am.validator.ShouldRefresh(cache.ExpiresAt, am.config.RefreshThreshold) {
		am.logger.Debug("Token refresh not needed yet")
		return nil
	}

	am.logger.Info("Token refresh threshold reached, refreshing tokens")
	return am.refreshTokens()
}

// ClearAuth clears all cached authentication state
func (am *DefaultAuthManager) ClearAuth() error {
	am.cacheMu.Lock()
	defer am.cacheMu.Unlock()

	am.cache = nil

	if err := ClearCache(am.logger); err != nil {
		return fmt.Errorf("failed to clear cache: %w", err)
	}

	am.logger.Info("Authentication cache cleared")
	return nil
}

// authenticate performs the full OIDC authentication flow
func (am *DefaultAuthManager) authenticate() error {
	am.refreshMu.Lock()
	defer am.refreshMu.Unlock()

	// Extract port from redirect URI
	callbackPort := 8765 // Default port
	// TODO: Parse from config.RedirectURI if needed

	cache, err := am.oidcClient.InitiateAuthFlow(callbackPort)
	if err != nil {
		return fmt.Errorf("authentication flow failed: %w", err)
	}

	am.cacheMu.Lock()
	am.cache = cache
	am.cacheMu.Unlock()

	am.logger.WithField("user_id", cache.UserID).Info("OIDC authentication completed")
	return nil
}

// refreshTokens refreshes the access token using the refresh token
func (am *DefaultAuthManager) refreshTokens() error {
	am.refreshMu.Lock()
	defer am.refreshMu.Unlock()

	am.cacheMu.RLock()
	cache := am.cache
	am.cacheMu.RUnlock()

	if cache == nil || cache.RefreshToken == "" {
		return fmt.Errorf("no refresh token available")
	}

	tokenResp, err := am.oidcClient.RefreshTokens(cache.RefreshToken)
	if err != nil {
		return fmt.Errorf("token refresh failed: %w", err)
	}

	// Update cache with new tokens
	expiresAt := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)

	am.cacheMu.Lock()
	am.cache.AccessToken = tokenResp.AccessToken
	am.cache.TokenType = tokenResp.TokenType
	am.cache.ExpiresAt = expiresAt
	if tokenResp.RefreshToken != "" {
		am.cache.RefreshToken = tokenResp.RefreshToken
	}
	if tokenResp.IDToken != "" {
		am.cache.IDToken = tokenResp.IDToken
	}
	am.cache.CachedAt = time.Now()

	// Clear Vault token since we have new OIDC tokens
	am.cache.VaultToken = ""
	am.cache.VaultTokenExpiresAt = time.Time{}

	if err := SaveCache(am.cache, am.logger); err != nil {
		am.logger.WithError(err).Warn("Failed to save refreshed tokens")
	}
	am.cacheMu.Unlock()

	am.logger.WithField("expires_at", expiresAt.Format(time.RFC3339)).Info("Tokens refreshed successfully")
	return nil
}

// authenticateVault authenticates with Vault using the OIDC access token
func (am *DefaultAuthManager) authenticateVault(accessToken string) (string, time.Time, error) {
	if accessToken == "" {
		return "", time.Time{}, fmt.Errorf("access token is empty")
	}

	vaultAddr := os.Getenv("VAULT_ADDR")
	if vaultAddr == "" {
		vaultAddr = "http://127.0.0.1:8200"
	}

	// Create config with the access token
	config := am.vaultJWTConfig
	config.JWTToken = accessToken
	config.Enabled = true

	am.logger.WithFields(log.Fields{
		"vault_addr": vaultAddr,
		"auth_path":  config.AuthPath,
		"role":       config.Role,
	}).Debug("Authenticating with Vault using JWT")

	// Authenticate with Vault
	client, err := AuthenticateWithJWT(vaultAddr, config, am.logger)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("Vault JWT authentication failed: %w", err)
	}

	vaultToken := client.Token()
	if vaultToken == "" {
		return "", time.Time{}, fmt.Errorf("no Vault token returned")
	}

	// Get token info to determine TTL
	tokenInfo, err := client.Auth().Token().LookupSelf()
	if err != nil {
		am.logger.WithError(err).Warn("Failed to lookup token info, using default TTL")
		// Default to 1 hour if we can't get the actual TTL
		vaultTokenExpiry := time.Now().Add(1 * time.Hour)
		return vaultToken, vaultTokenExpiry, nil
	}

	// Extract TTL from token info
	ttl := int64(3600) // Default 1 hour
	if ttlData, ok := tokenInfo.Data["ttl"].(json.Number); ok {
		if parsedTTL, err := ttlData.Int64(); err == nil {
			ttl = parsedTTL
		}
	}

	vaultTokenExpiry := time.Now().Add(time.Duration(ttl) * time.Second)

	am.logger.WithFields(log.Fields{
		"ttl":        ttl,
		"expires_at": vaultTokenExpiry.Format(time.RFC3339),
	}).Info("Vault authentication successful")

	return vaultToken, vaultTokenExpiry, nil
}
