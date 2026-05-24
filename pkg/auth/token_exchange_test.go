// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadTokenExchangeConfigFromEnv(t *testing.T) {
	// Save original env vars
	originalEnabled := os.Getenv("TOKEN_EXCHANGE_ENABLED")
	originalBrokerURL := os.Getenv("TOKEN_EXCHANGE_BROKER_URL")
	originalClientID := os.Getenv("TOKEN_EXCHANGE_CLIENT_ID")
	originalAudience := os.Getenv("TOKEN_EXCHANGE_AUDIENCE")
	originalScopes := os.Getenv("TOKEN_EXCHANGE_SCOPES")

	// Clean up
	defer func() {
		os.Setenv("TOKEN_EXCHANGE_ENABLED", originalEnabled)
		os.Setenv("TOKEN_EXCHANGE_BROKER_URL", originalBrokerURL)
		os.Setenv("TOKEN_EXCHANGE_CLIENT_ID", originalClientID)
		os.Setenv("TOKEN_EXCHANGE_AUDIENCE", originalAudience)
		os.Setenv("TOKEN_EXCHANGE_SCOPES", originalScopes)
	}()

	t.Run("loads config from environment", func(t *testing.T) {
		os.Setenv("TOKEN_EXCHANGE_ENABLED", "true")
		os.Setenv("TOKEN_EXCHANGE_BROKER_URL", "https://broker.example.com/token")
		os.Setenv("TOKEN_EXCHANGE_CLIENT_ID", "test-client")
		os.Setenv("TOKEN_EXCHANGE_AUDIENCE", "vault")
		os.Setenv("TOKEN_EXCHANGE_SCOPES", "vault:read,vault:write")

		config := LoadTokenExchangeConfigFromEnv()

		assert.True(t, config.Enabled)
		assert.Equal(t, "https://broker.example.com/token", config.BrokerURL)
		assert.Equal(t, "test-client", config.ClientID)
		assert.Equal(t, "vault", config.Audience)
		assert.Equal(t, []string{"vault:read", "vault:write"}, config.RequestedScopes)
	})

	t.Run("uses default values", func(t *testing.T) {
		os.Unsetenv("TOKEN_EXCHANGE_ENABLED")
		os.Unsetenv("TOKEN_EXCHANGE_AUDIENCE")
		os.Unsetenv("TOKEN_EXCHANGE_SCOPES")

		config := LoadTokenExchangeConfigFromEnv()

		assert.False(t, config.Enabled)
		assert.Equal(t, "vault", config.Audience)
		assert.Equal(t, []string{"vault:read", "vault:write"}, config.RequestedScopes)
	})
}

func TestBasicTokenValidation(t *testing.T) {
	logger := log.New()
	logger.SetLevel(log.ErrorLevel)

	config := TokenExchangeConfig{
		Enabled: true,
	}

	service := NewTokenExchangeService(config, logger)

	t.Run("validates valid JWT", func(t *testing.T) {
		// Create a test JWT
		claims := jwt.MapClaims{
			"sub": "user123",
			"iss": "https://idp.example.com",
			"aud": "vault",
			"exp": time.Now().Add(1 * time.Hour).Unix(),
			"iat": time.Now().Unix(),
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString([]byte("test-secret"))
		require.NoError(t, err)

		// Validate the token
		result, err := service.basicTokenValidation(tokenString)
		require.NoError(t, err)
		assert.True(t, result.Active)
		assert.Equal(t, "user123", result.Sub)
		assert.Equal(t, "https://idp.example.com", result.Iss)
		assert.Contains(t, result.Aud, "vault")
	})

	t.Run("marks expired token as inactive", func(t *testing.T) {
		// Create an expired JWT
		claims := jwt.MapClaims{
			"sub": "user123",
			"exp": time.Now().Add(-1 * time.Hour).Unix(),
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString([]byte("test-secret"))
		require.NoError(t, err)

		// Validate the token
		result, err := service.basicTokenValidation(tokenString)
		require.NoError(t, err)
		assert.False(t, result.Active, "Expired token should be marked as inactive")
	})

	t.Run("handles invalid JWT", func(t *testing.T) {
		_, err := service.basicTokenValidation("invalid-token")
		assert.Error(t, err)
	})
}

func TestTokenExchange(t *testing.T) {
	logger := log.New()
	logger.SetLevel(log.ErrorLevel)

	t.Run("exchanges token successfully", func(t *testing.T) {
		// Mock token broker server
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Verify request
			assert.Equal(t, "POST", r.Method)
			assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))

			// Parse form data
			err := r.ParseForm()
			require.NoError(t, err)

			assert.Equal(t, GrantTypeTokenExchange, r.FormValue("grant_type"))
			assert.Equal(t, TokenTypeIDToken, r.FormValue("subject_token_type"))
			assert.NotEmpty(t, r.FormValue("subject_token"))

			// Return mock response
			response := TokenExchangeResponse{
				AccessToken:     "exchanged-token",
				IssuedTokenType: TokenTypeJWT,
				TokenType:       "Bearer",
				ExpiresIn:       3600,
				Scope:           "vault:read vault:write",
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
		}))
		defer server.Close()

		config := TokenExchangeConfig{
			Enabled:         true,
			BrokerURL:       server.URL,
			ClientID:        "test-client",
			ClientSecret:    "test-secret",
			Audience:        "vault",
			RequestedScopes: []string{"vault:read", "vault:write"},
		}

		service := NewTokenExchangeService(config, logger)

		// Create a test ID token
		claims := jwt.MapClaims{
			"sub": "user123",
			"exp": time.Now().Add(1 * time.Hour).Unix(),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		idToken, err := token.SignedString([]byte("test-secret"))
		require.NoError(t, err)

		// Exchange token
		ctx := context.Background()
		result, err := service.ExchangeToken(ctx, idToken)

		require.NoError(t, err)
		assert.Equal(t, "exchanged-token", result.AccessToken)
		assert.Equal(t, "Bearer", result.TokenType)
		assert.Equal(t, 3600, result.ExpiresIn)
	})

	t.Run("returns error when exchange disabled", func(t *testing.T) {
		config := TokenExchangeConfig{
			Enabled: false,
		}

		service := NewTokenExchangeService(config, logger)

		ctx := context.Background()
		_, err := service.ExchangeToken(ctx, "test-token")

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not enabled")
	})

	t.Run("handles broker error", func(t *testing.T) {
		// Mock error response
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"invalid_client"}`))
		}))
		defer server.Close()

		config := TokenExchangeConfig{
			Enabled:   true,
			BrokerURL: server.URL,
		}

		service := NewTokenExchangeService(config, logger)

		// Create a test token
		claims := jwt.MapClaims{
			"sub": "user123",
			"exp": time.Now().Add(1 * time.Hour).Unix(),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		idToken, err := token.SignedString([]byte("test-secret"))
		require.NoError(t, err)

		ctx := context.Background()
		_, err = service.ExchangeToken(ctx, idToken)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed with status 401")
	})
}

func TestExchangeForVaultToken(t *testing.T) {
	logger := log.New()
	logger.SetLevel(log.ErrorLevel)

	t.Run("uses ID token directly when exchange disabled", func(t *testing.T) {
		config := TokenExchangeConfig{
			Enabled: false,
		}

		service := NewTokenExchangeService(config, logger)

		ctx := context.Background()
		result, err := service.ExchangeForVaultToken(ctx, "test-id-token")

		require.NoError(t, err)
		assert.Equal(t, "test-id-token", result)
	})

	t.Run("exchanges token when enabled", func(t *testing.T) {
		// Mock successful exchange
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			response := TokenExchangeResponse{
				AccessToken: "vault-jwt-token",
				TokenType:   "Bearer",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
		}))
		defer server.Close()

		config := TokenExchangeConfig{
			Enabled:   true,
			BrokerURL: server.URL,
		}

		service := NewTokenExchangeService(config, logger)

		// Create a test token
		claims := jwt.MapClaims{
			"sub": "user123",
			"exp": time.Now().Add(1 * time.Hour).Unix(),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		idToken, err := token.SignedString([]byte("test-secret"))
		require.NoError(t, err)

		ctx := context.Background()
		result, err := service.ExchangeForVaultToken(ctx, idToken)

		require.NoError(t, err)
		assert.Equal(t, "vault-jwt-token", result)
	})
}

func TestTokenIntrospection(t *testing.T) {
	logger := log.New()
	logger.SetLevel(log.ErrorLevel)

	t.Run("introspects token via endpoint", func(t *testing.T) {
		// Mock introspection server
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)

			response := TokenIntrospectionResponse{
				Active:   true,
				Sub:      "user123",
				Scope:    "vault:read vault:write",
				Exp:      time.Now().Add(1 * time.Hour).Unix(),
				ClientID: "test-client",
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
		}))
		defer server.Close()

		config := TokenExchangeConfig{
			Enabled:          true,
			IntrospectionURL: server.URL,
			ClientID:         "test-client",
			ClientSecret:     "test-secret",
		}

		service := NewTokenExchangeService(config, logger)

		ctx := context.Background()
		result, err := service.IntrospectToken(ctx, "test-token", "id_token")

		require.NoError(t, err)
		assert.True(t, result.Active)
		assert.Equal(t, "user123", result.Sub)
		assert.Equal(t, "vault:read vault:write", result.Scope)
	})

	t.Run("falls back to basic validation", func(t *testing.T) {
		config := TokenExchangeConfig{
			Enabled: true,
			// No introspection URL
		}

		service := NewTokenExchangeService(config, logger)

		// Create a test token
		claims := jwt.MapClaims{
			"sub": "user123",
			"exp": time.Now().Add(1 * time.Hour).Unix(),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString([]byte("test-secret"))
		require.NoError(t, err)

		ctx := context.Background()
		result, err := service.IntrospectToken(ctx, tokenString, "id_token")

		require.NoError(t, err)
		assert.True(t, result.Active)
		assert.Equal(t, "user123", result.Sub)
	})
}
