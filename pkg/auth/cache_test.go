// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package auth

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
)

func getTestLogger() *log.Logger {
	logger := log.New()
	logger.SetLevel(log.WarnLevel) // Reduce noise in tests
	return logger
}

func cleanupTestCache(t *testing.T) {
	cacheDir, err := getCacheDir()
	if err != nil {
		t.Logf("Warning: Could not get cache dir: %v", err)
		return
	}

	os.Remove(filepath.Join(cacheDir, AuthCacheFileName))
	os.Remove(filepath.Join(cacheDir, PKCEStateFileName))
}

func TestSaveAndLoadCache(t *testing.T) {
	defer cleanupTestCache(t)
	logger := getTestLogger()

	now := time.Now()
	expiresAt := now.Add(1 * time.Hour)

	cache := &TokenCache{
		AccessToken:         "test_access_token",
		RefreshToken:        "test_refresh_token",
		IDToken:             "test_id_token",
		TokenType:           "Bearer",
		ExpiresAt:           expiresAt,
		VaultToken:          "test_vault_token",
		VaultTokenExpiresAt: expiresAt.Add(30 * time.Minute),
		UserID:              "test_user_123",
	}

	// Save cache
	err := SaveCache(cache, logger)
	if err != nil {
		t.Fatalf("Failed to save cache: %v", err)
	}

	// Load cache
	loadedCache, err := LoadCache(logger)
	if err != nil {
		t.Fatalf("Failed to load cache: %v", err)
	}

	if loadedCache == nil {
		t.Fatal("Loaded cache is nil")
	}

	// Verify fields
	if loadedCache.AccessToken != cache.AccessToken {
		t.Errorf("AccessToken mismatch: got %s, want %s", loadedCache.AccessToken, cache.AccessToken)
	}

	if loadedCache.RefreshToken != cache.RefreshToken {
		t.Errorf("RefreshToken mismatch: got %s, want %s", loadedCache.RefreshToken, cache.RefreshToken)
	}

	if loadedCache.IDToken != cache.IDToken {
		t.Errorf("IDToken mismatch: got %s, want %s", loadedCache.IDToken, cache.IDToken)
	}

	if loadedCache.UserID != cache.UserID {
		t.Errorf("UserID mismatch: got %s, want %s", loadedCache.UserID, cache.UserID)
	}

	if loadedCache.VaultToken != cache.VaultToken {
		t.Errorf("VaultToken mismatch: got %s, want %s", loadedCache.VaultToken, cache.VaultToken)
	}

	// Check that CachedAt was set
	if loadedCache.CachedAt.IsZero() {
		t.Error("CachedAt timestamp is zero")
	}
}

func TestLoadNonexistentCache(t *testing.T) {
	defer cleanupTestCache(t)
	logger := getTestLogger()

	cache, err := LoadCache(logger)
	if err != nil {
		t.Fatalf("Expected no error for nonexistent cache, got: %v", err)
	}

	if cache != nil {
		t.Errorf("Expected nil cache for nonexistent file, got: %+v", cache)
	}
}

func TestClearCache(t *testing.T) {
	defer cleanupTestCache(t)
	logger := getTestLogger()

	cache := &TokenCache{
		AccessToken: "test_token",
		ExpiresAt:   time.Now().Add(1 * time.Hour),
	}

	// Save cache
	err := SaveCache(cache, logger)
	if err != nil {
		t.Fatalf("Failed to save cache: %v", err)
	}

	// Verify it exists
	loadedCache, err := LoadCache(logger)
	if err != nil || loadedCache == nil {
		t.Fatal("Cache should exist after saving")
	}

	// Clear cache
	err = ClearCache(logger)
	if err != nil {
		t.Fatalf("Failed to clear cache: %v", err)
	}

	// Verify it's gone
	loadedCache, err = LoadCache(logger)
	if err != nil {
		t.Fatalf("Expected no error after clearing cache, got: %v", err)
	}
	if loadedCache != nil {
		t.Error("Cache should be nil after clearing")
	}
}

func TestTokenCacheIsExpired(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt time.Time
		want      bool
	}{
		{
			name:      "expired token",
			expiresAt: time.Now().Add(-1 * time.Hour),
			want:      true,
		},
		{
			name:      "valid token",
			expiresAt: time.Now().Add(1 * time.Hour),
			want:      false,
		},
		{
			name:      "just expired",
			expiresAt: time.Now().Add(-1 * time.Second),
			want:      true,
		},
		{
			name:      "expires soon",
			expiresAt: time.Now().Add(1 * time.Minute),
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := &TokenCache{
				AccessToken: "test_token",
				ExpiresAt:   tt.expiresAt,
			}

			got := cache.IsExpired()
			if got != tt.want {
				t.Errorf("IsExpired() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTokenCacheIsValid(t *testing.T) {
	tests := []struct {
		name      string
		cache     *TokenCache
		want      bool
	}{
		{
			name: "valid cache",
			cache: &TokenCache{
				AccessToken: "test_token",
				ExpiresAt:   time.Now().Add(1 * time.Hour),
			},
			want: true,
		},
		{
			name: "expired cache",
			cache: &TokenCache{
				AccessToken: "test_token",
				ExpiresAt:   time.Now().Add(-1 * time.Hour),
			},
			want: false,
		},
		{
			name: "missing access token",
			cache: &TokenCache{
				AccessToken: "",
				ExpiresAt:   time.Now().Add(1 * time.Hour),
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.cache.IsValid()
			if got != tt.want {
				t.Errorf("IsValid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSaveAndLoadPKCEState(t *testing.T) {
	defer cleanupTestCache(t)
	logger := getTestLogger()

	now := time.Now()
	state := &PKCEState{
		CodeVerifier: "test_verifier_12345",
		State:        "test_state_67890",
		CreatedAt:    now,
		ExpiresAt:    now.Add(10 * time.Minute),
	}

	// Save PKCE state
	err := SavePKCEState(state, logger)
	if err != nil {
		t.Fatalf("Failed to save PKCE state: %v", err)
	}

	// Load PKCE state
	loadedState, err := LoadPKCEState(logger)
	if err != nil {
		t.Fatalf("Failed to load PKCE state: %v", err)
	}

	if loadedState == nil {
		t.Fatal("Loaded PKCE state is nil")
	}

	// Verify fields
	if loadedState.CodeVerifier != state.CodeVerifier {
		t.Errorf("CodeVerifier mismatch: got %s, want %s", loadedState.CodeVerifier, state.CodeVerifier)
	}

	if loadedState.State != state.State {
		t.Errorf("State mismatch: got %s, want %s", loadedState.State, state.State)
	}
}

func TestLoadExpiredPKCEState(t *testing.T) {
	defer cleanupTestCache(t)
	logger := getTestLogger()

	now := time.Now()
	state := &PKCEState{
		CodeVerifier: "test_verifier",
		State:        "test_state",
		CreatedAt:    now.Add(-15 * time.Minute),
		ExpiresAt:    now.Add(-5 * time.Minute), // Expired 5 minutes ago
	}

	// Save expired PKCE state
	err := SavePKCEState(state, logger)
	if err != nil {
		t.Fatalf("Failed to save PKCE state: %v", err)
	}

	// Load PKCE state - should return nil for expired state
	loadedState, err := LoadPKCEState(logger)
	if err != nil {
		t.Fatalf("Expected no error for expired state, got: %v", err)
	}

	if loadedState != nil {
		t.Error("Expected nil for expired PKCE state")
	}
}

func TestClearPKCEState(t *testing.T) {
	defer cleanupTestCache(t)
	logger := getTestLogger()

	state := &PKCEState{
		CodeVerifier: "test_verifier",
		State:        "test_state",
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(10 * time.Minute),
	}

	// Save PKCE state
	err := SavePKCEState(state, logger)
	if err != nil {
		t.Fatalf("Failed to save PKCE state: %v", err)
	}

	// Clear PKCE state
	err = ClearPKCEState(logger)
	if err != nil {
		t.Fatalf("Failed to clear PKCE state: %v", err)
	}

	// Verify it's gone
	loadedState, err := LoadPKCEState(logger)
	if err != nil {
		t.Fatalf("Expected no error after clearing, got: %v", err)
	}
	if loadedState != nil {
		t.Error("PKCE state should be nil after clearing")
	}
}

func TestCacheDirectoryPermissions(t *testing.T) {
	cacheDir, err := getCacheDir()
	if err != nil {
		t.Fatalf("Failed to get cache dir: %v", err)
	}

	info, err := os.Stat(cacheDir)
	if err != nil {
		t.Fatalf("Failed to stat cache dir: %v", err)
	}

	// Verify directory permissions are 0700 (owner read/write/execute only)
	mode := info.Mode().Perm()
	expected := os.FileMode(0700)
	if mode != expected {
		t.Errorf("Cache directory permissions are %o, expected %o", mode, expected)
	}
}
