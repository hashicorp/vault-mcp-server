// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestGetEnv(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		fallback string
		expected string
	}{
		{
			name:     "returns fallback when env var not set",
			key:      "NON_EXISTENT_VAR",
			fallback: "default_value",
			expected: "default_value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getEnv(tt.key, tt.fallback)
			if result != tt.expected {
				t.Errorf("getEnv() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestNewVaultClient(t *testing.T) {
	// This is a basic test that checks if the function doesn't panic
	// In a real scenario, you'd want to mock the Vault API
	sessionID := "test-session"
	vaultAddress := "http://127.0.0.1:8200"
	vaultToken := "test-token"
	vaultNamespace := "test-namespace"

	client, err := NewVaultClient(sessionID, vaultAddress, false, vaultToken, vaultNamespace)
	if err != nil {
		t.Logf("NewVaultClient() error = %v (expected in test environment)", err)
	}

	if client != nil {
		// Clean up
		DeleteVaultClient(sessionID)
	}
}

func TestVaultNamespaceSupport(t *testing.T) {
	logger := log.New()
	logger.SetLevel(log.ErrorLevel)

	t.Run("namespace via header", func(t *testing.T) {
		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			namespace := ctx.Value(contextKey(VaultNamespace))
			assert.Equal(t, "test-namespace", namespace)
			w.WriteHeader(http.StatusOK)
		})

		middleware := VaultContextMiddleware(logger)
		handler := middleware(mockHandler)

		req := httptest.NewRequest("GET", "/mcp", nil)
		req.Header.Set(VaultHeaderNamespace, "test-namespace")

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("namespace via environment variable", func(t *testing.T) {
		os.Setenv(VaultNamespace, "env-namespace")
		defer os.Unsetenv(VaultNamespace)

		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			namespace := ctx.Value(contextKey(VaultNamespace))
			assert.Equal(t, "env-namespace", namespace)
			w.WriteHeader(http.StatusOK)
		})

		middleware := VaultContextMiddleware(logger)
		handler := middleware(mockHandler)

		req := httptest.NewRequest("GET", "/mcp", nil)

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("header takes precedence over environment", func(t *testing.T) {
		os.Setenv(VaultNamespace, "env-namespace")
		defer os.Unsetenv(VaultNamespace)

		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			namespace := ctx.Value(contextKey(VaultNamespace))
			assert.Equal(t, "header-namespace", namespace)
			w.WriteHeader(http.StatusOK)
		})

		middleware := VaultContextMiddleware(logger)
		handler := middleware(mockHandler)

		req := httptest.NewRequest("GET", "/mcp", nil)
		req.Header.Set(VaultHeaderNamespace, "header-namespace")

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})
}
