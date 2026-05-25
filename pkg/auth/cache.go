// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package auth

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	// DefaultCacheDir is the default directory for auth cache files
	DefaultCacheDir = ".vault-mcp"

	// AuthCacheFileName is the name of the auth cache file
	AuthCacheFileName = "auth-cache.json"

	// PKCEStateFileName is the name of the PKCE state file
	PKCEStateFileName = "pkce-state.json"
)

// TokenCache represents cached authentication tokens
type TokenCache struct {
	// OIDC tokens
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	IDToken      string    `json:"id_token,omitempty"`
	TokenType    string    `json:"token_type,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`

	// Vault token
	VaultToken          string    `json:"vault_token,omitempty"`
	VaultTokenExpiresAt time.Time `json:"vault_token_expires_at,omitempty"`

	// User identity (for future multi-user support)
	UserID string `json:"user_id,omitempty"` // OIDC sub claim

	// Metadata
	CachedAt time.Time `json:"cached_at"`
}

// PKCEState represents PKCE state for in-flight auth flows
type PKCEState struct {
	CodeVerifier string    `json:"code_verifier"`
	State        string    `json:"state"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"` // Auto-cleanup after 10 minutes
}

// getCacheDir returns the cache directory path, creating it if necessary
func getCacheDir() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}

	cacheDir := filepath.Join(homeDir, DefaultCacheDir)

	// Create directory if it doesn't exist
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		return "", fmt.Errorf("failed to create cache directory: %w", err)
	}

	return cacheDir, nil
}

// SaveCache persists the token cache to disk
func SaveCache(cache *TokenCache, logger *log.Logger) error {
	cacheDir, err := getCacheDir()
	if err != nil {
		return err
	}

	cachePath := filepath.Join(cacheDir, AuthCacheFileName)

	// Update cached timestamp
	cache.CachedAt = time.Now()

	// Marshal to JSON with indentation for readability
	data, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal cache: %w", err)
	}

	// Write to file with restricted permissions (owner read/write only)
	if err := os.WriteFile(cachePath, data, 0600); err != nil {
		return fmt.Errorf("failed to write cache file: %w", err)
	}

	logger.WithField("path", cachePath).Debug("Token cache saved")
	return nil
}

// LoadCache loads the token cache from disk
func LoadCache(logger *log.Logger) (*TokenCache, error) {
	cacheDir, err := getCacheDir()
	if err != nil {
		return nil, err
	}

	cachePath := filepath.Join(cacheDir, AuthCacheFileName)

	// Check if cache file exists
	if _, err := os.Stat(cachePath); os.IsNotExist(err) {
		logger.Debug("No cache file found")
		return nil, nil
	}

	// Read cache file
	data, err := os.ReadFile(cachePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read cache file: %w", err)
	}

	// Unmarshal JSON
	var cache TokenCache
	if err := json.Unmarshal(data, &cache); err != nil {
		return nil, fmt.Errorf("failed to unmarshal cache: %w", err)
	}

	logger.WithField("path", cachePath).Debug("Token cache loaded")
	return &cache, nil
}

// ClearCache removes the token cache file
func ClearCache(logger *log.Logger) error {
	cacheDir, err := getCacheDir()
	if err != nil {
		return err
	}

	cachePath := filepath.Join(cacheDir, AuthCacheFileName)

	if err := os.Remove(cachePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove cache file: %w", err)
	}

	logger.WithField("path", cachePath).Info("Token cache cleared")
	return nil
}

// SavePKCEState persists PKCE state to disk
func SavePKCEState(state *PKCEState, logger *log.Logger) error {
	cacheDir, err := getCacheDir()
	if err != nil {
		return err
	}

	statePath := filepath.Join(cacheDir, PKCEStateFileName)

	// Marshal to JSON
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal PKCE state: %w", err)
	}

	// Write to file with restricted permissions
	if err := os.WriteFile(statePath, data, 0600); err != nil {
		return fmt.Errorf("failed to write PKCE state file: %w", err)
	}

	logger.WithField("path", statePath).Debug("PKCE state saved")
	return nil
}

// LoadPKCEState loads PKCE state from disk
func LoadPKCEState(logger *log.Logger) (*PKCEState, error) {
	cacheDir, err := getCacheDir()
	if err != nil {
		return nil, err
	}

	statePath := filepath.Join(cacheDir, PKCEStateFileName)

	// Check if state file exists
	if _, err := os.Stat(statePath); os.IsNotExist(err) {
		logger.Debug("No PKCE state file found")
		return nil, nil
	}

	// Read state file
	data, err := os.ReadFile(statePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read PKCE state file: %w", err)
	}

	// Unmarshal JSON
	var state PKCEState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("failed to unmarshal PKCE state: %w", err)
	}

	// Check if state has expired (10 minute timeout)
	if time.Now().After(state.ExpiresAt) {
		logger.Warn("PKCE state has expired, clearing")
		if err := ClearPKCEState(logger); err != nil {
			logger.WithError(err).Warn("Failed to clear expired PKCE state")
		}
		return nil, nil
	}

	logger.WithField("path", statePath).Debug("PKCE state loaded")
	return &state, nil
}

// ClearPKCEState removes the PKCE state file
func ClearPKCEState(logger *log.Logger) error {
	cacheDir, err := getCacheDir()
	if err != nil {
		return err
	}

	statePath := filepath.Join(cacheDir, PKCEStateFileName)

	if err := os.Remove(statePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove PKCE state file: %w", err)
	}

	logger.WithField("path", statePath).Debug("PKCE state cleared")
	return nil
}

// IsExpired checks if the token cache has expired
func (tc *TokenCache) IsExpired() bool {
	return time.Now().After(tc.ExpiresAt)
}

// IsVaultTokenExpired checks if the Vault token has expired
func (tc *TokenCache) IsVaultTokenExpired() bool {
	if tc.VaultToken == "" {
		return true
	}
	return time.Now().After(tc.VaultTokenExpiresAt)
}

// IsValid checks if the token cache is valid and not expired
func (tc *TokenCache) IsValid() bool {
	return tc.AccessToken != "" && !tc.IsExpired()
}
