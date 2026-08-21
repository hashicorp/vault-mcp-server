// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func resetJWTCache() {
	jwtTokenCache = sync.Map{}
}

func testLogger() *log.Logger {
	logger := log.New()
	logger.SetOutput(os.Stdout)
	logger.SetLevel(log.ErrorLevel)
	return logger
}

func TestExtractBearerToken(t *testing.T) {
	tests := []struct {
		name      string
		header    string
		wantToken string
		wantErr   bool
	}{
		{"bearer prefix", "Bearer abc.def.ghi", "abc.def.ghi", false},
		{"bare token", "abc.def.ghi", "abc.def.ghi", false},
		{"empty header", "", "", true},
		{"bearer with no token", "Bearer ", "", true},
		{"whitespace only", "   ", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := extractBearerToken(tt.header)
			if tt.wantErr {
				require.Error(t, err)
				var loginErr *jwtLoginError
				require.ErrorAs(t, err, &loginErr)
				assert.Equal(t, http.StatusUnauthorized, loginErr.StatusCode())
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantToken, token)
		})
	}
}

func TestExchangeJWTForVaultToken(t *testing.T) {
	t.Run("missing role is rejected before any request is made", func(t *testing.T) {
		os.Unsetenv(VaultAuthJWTRole)
		_, _, err := exchangeJWTForVaultToken("http://127.0.0.1:1", "", false, "some.jwt.token")
		require.Error(t, err)
		var loginErr *jwtLoginError
		require.ErrorAs(t, err, &loginErr)
		assert.Equal(t, http.StatusUnauthorized, loginErr.StatusCode())
		assert.Contains(t, loginErr.Error(), "VAULT_AUTH_JWT_ROLE")
	})

	t.Run("successful login returns token and lease", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/v1/auth/jwt/login", r.URL.Path)

			var body map[string]string
			require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
			assert.Equal(t, "my-role", body["role"])
			assert.Equal(t, "my.jwt.token", body["jwt"])

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"auth": map[string]interface{}{
					"client_token":   "s.generated-token",
					"lease_duration": 3600,
				},
			})
		}))
		defer server.Close()

		os.Setenv(VaultAuthJWTRole, "my-role")
		defer os.Unsetenv(VaultAuthJWTRole)

		token, lease, err := exchangeJWTForVaultToken(server.URL, "", false, "my.jwt.token")
		require.NoError(t, err)
		assert.Equal(t, "s.generated-token", token)
		assert.Equal(t, 3600*time.Second, lease)
	})

	t.Run("custom mount path is used", func(t *testing.T) {
		var gotPath string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotPath = r.URL.Path
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"auth": map[string]interface{}{
					"client_token":   "s.token",
					"lease_duration": 60,
				},
			})
		}))
		defer server.Close()

		os.Setenv(VaultAuthJWTRole, "my-role")
		os.Setenv(VaultAuthJWTPath, "custom-jwt-mount")
		defer os.Unsetenv(VaultAuthJWTRole)
		defer os.Unsetenv(VaultAuthJWTPath)

		_, _, err := exchangeJWTForVaultToken(server.URL, "", false, "jwt")
		require.NoError(t, err)
		assert.Equal(t, "/v1/auth/custom-jwt-mount/login", gotPath)
	})

	t.Run("403 from vault is surfaced as forbidden", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"errors": []string{"permission denied"},
			})
		}))
		defer server.Close()

		os.Setenv(VaultAuthJWTRole, "my-role")
		defer os.Unsetenv(VaultAuthJWTRole)

		_, _, err := exchangeJWTForVaultToken(server.URL, "", false, "bad.jwt.token")
		require.Error(t, err)
		var loginErr *jwtLoginError
		require.ErrorAs(t, err, &loginErr)
		assert.Equal(t, http.StatusForbidden, loginErr.StatusCode())
		assert.Contains(t, loginErr.Error(), "permission denied")
	})

	t.Run("400 from vault is surfaced as unauthorized", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"errors": []string{"missing jwt"},
			})
		}))
		defer server.Close()

		os.Setenv(VaultAuthJWTRole, "my-role")
		defer os.Unsetenv(VaultAuthJWTRole)

		_, _, err := exchangeJWTForVaultToken(server.URL, "", false, "")
		require.Error(t, err)
		var loginErr *jwtLoginError
		require.ErrorAs(t, err, &loginErr)
		assert.Equal(t, http.StatusUnauthorized, loginErr.StatusCode())
	})

	t.Run("unreachable vault is surfaced as service unavailable", func(t *testing.T) {
		os.Setenv(VaultAuthJWTRole, "my-role")
		defer os.Unsetenv(VaultAuthJWTRole)

		_, _, err := exchangeJWTForVaultToken("http://127.0.0.1:1", "", false, "some.jwt.token")
		require.Error(t, err)
		var loginErr *jwtLoginError
		require.ErrorAs(t, err, &loginErr)
		assert.Equal(t, http.StatusServiceUnavailable, loginErr.StatusCode())
	})
}

func TestResolveJWTVaultToken(t *testing.T) {
	logger := testLogger()

	t.Run("caches token across calls with the same jwt", func(t *testing.T) {
		resetJWTCache()
		var loginCalls int
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			loginCalls++
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"auth": map[string]interface{}{
					"client_token":   "s.cached-token",
					"lease_duration": 3600,
				},
			})
		}))
		defer server.Close()

		os.Setenv(VaultAuthJWTRole, "my-role")
		defer os.Unsetenv(VaultAuthJWTRole)

		token1, err := resolveJWTVaultToken(server.URL, "", false, "same.jwt.token", logger)
		require.NoError(t, err)
		token2, err := resolveJWTVaultToken(server.URL, "", false, "same.jwt.token", logger)
		require.NoError(t, err)

		assert.Equal(t, token1, token2)
		assert.Equal(t, 1, loginCalls)
	})

	t.Run("does not cache a lease shorter than the safety margin", func(t *testing.T) {
		resetJWTCache()
		var loginCalls int
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			loginCalls++
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"auth": map[string]interface{}{
					"client_token":   "s.short-lived-token",
					"lease_duration": 5,
				},
			})
		}))
		defer server.Close()

		os.Setenv(VaultAuthJWTRole, "my-role")
		defer os.Unsetenv(VaultAuthJWTRole)

		_, err := resolveJWTVaultToken(server.URL, "", false, "short.jwt.token", logger)
		require.NoError(t, err)
		_, err = resolveJWTVaultToken(server.URL, "", false, "short.jwt.token", logger)
		require.NoError(t, err)

		assert.Equal(t, 2, loginCalls)
	})

	t.Run("different jwts get independent cache entries", func(t *testing.T) {
		resetJWTCache()
		var loginCalls int
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			loginCalls++
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"auth": map[string]interface{}{
					"client_token":   "s.token-for-user",
					"lease_duration": 3600,
				},
			})
		}))
		defer server.Close()

		os.Setenv(VaultAuthJWTRole, "my-role")
		defer os.Unsetenv(VaultAuthJWTRole)

		_, err := resolveJWTVaultToken(server.URL, "", false, "user-a.jwt", logger)
		require.NoError(t, err)
		_, err = resolveJWTVaultToken(server.URL, "", false, "user-b.jwt", logger)
		require.NoError(t, err)

		assert.Equal(t, 2, loginCalls)
	})

	t.Run("VAULT_AUTH_JWT_CACHE_TTL caps the cache lifetime", func(t *testing.T) {
		resetJWTCache()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"auth": map[string]interface{}{
					"client_token":   "s.capped-token",
					"lease_duration": 3600,
				},
			})
		}))
		defer server.Close()

		os.Setenv(VaultAuthJWTRole, "my-role")
		os.Setenv(VaultAuthJWTCacheTTL, "20")
		defer os.Unsetenv(VaultAuthJWTRole)
		defer os.Unsetenv(VaultAuthJWTCacheTTL)

		before := time.Now()
		_, err := resolveJWTVaultToken(server.URL, "", false, "capped.jwt", logger)
		require.NoError(t, err)

		value, ok := jwtTokenCache.Load(cacheKey("capped.jwt"))
		require.True(t, ok)
		entry := value.(cachedToken)
		// Lease was 3600s but the cap is 20s, so the cache entry should
		// expire in roughly cap-margin seconds, not close to an hour.
		assert.WithinDuration(t, before.Add(20*time.Second-cacheSafetyMargin), entry.expiresAt, 2*time.Second)
	})

	t.Run("login failure is propagated and nothing is cached", func(t *testing.T) {
		resetJWTCache()
		os.Unsetenv(VaultAuthJWTRole)

		_, err := resolveJWTVaultToken("http://127.0.0.1:1", "", false, "unconfigured.jwt", logger)
		require.Error(t, err)

		_, ok := jwtTokenCache.Load(cacheKey("unconfigured.jwt"))
		assert.False(t, ok)
	})
}
