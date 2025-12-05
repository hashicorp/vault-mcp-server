// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestVaultContextMiddleware(t *testing.T) {
	logger := log.New()
	logger.SetOutput(os.Stdout)

	tests := []struct {
		name             string
		headers          map[string]string
		queryParams      map[string]string
		envVars          map[string]string
		expectedAddr     string
		expectedToken    string
		expectedResponse int
	}{
		{
			name: "headers take precedence",
			headers: map[string]string{
				"VAULT_ADDR":        "http://header-vault:8200",
				"VAULT_TOKEN":       "header-token",
				"X-Vault-Namespace": "header-namespace",
			},
			queryParams: map[string]string{
				"VAULT_ADDR":      "http://query-vault:8200",
				"VAULT_TOKEN":     "query-token",
				"VAULT_NAMESPACE": "query-namespace",
			},
			expectedAddr:     "http://header-vault:8200",
			expectedToken:    "header-token",
			expectedResponse: 200,
		},
		{
			name: "query params when no headers",
			queryParams: map[string]string{
				"VAULT_ADDR":  "http://query-vault:8200",
				"VAULT_TOKEN": "query-token",
			},
			expectedAddr:     "http://query-vault:8200",
			expectedToken:    "query-token",
			expectedResponse: 400,
		},
		{
			name: "environment variables as fallback",
			envVars: map[string]string{
				"VAULT_ADDR":      "http://env-vault:8200",
				"VAULT_TOKEN":     "env-token",
				"VAULT_NAMESPACE": "env-namespace",
			},
			expectedAddr:     "http://env-vault:8200",
			expectedToken:    "env-token",
			expectedResponse: 200,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up environment variables
			for key, value := range tt.envVars {
				os.Setenv(key, value)
				defer os.Unsetenv(key)
			}

			// Create test handler that checks context values
			testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ctx := r.Context()

				addr, ok := ctx.Value(contextKey(VaultAddress)).(string)
				if !ok {
					addr = ""
				}

				token, ok := ctx.Value(contextKey(VaultToken)).(string)
				if !ok {
					token = ""
				}

				namespace, ok := ctx.Value(contextKey(VaultNamespace)).(string)
				if !ok {
					namespace = ""
				}

				if addr != tt.expectedAddr {
					t.Errorf("Expected VAULT_ADDR %s, got %s", tt.expectedAddr, addr)
				}

				if token != tt.expectedToken {
					t.Errorf("Expected VAULT_TOKEN %s, got %s", tt.expectedToken, token)
				}

				// Check namespace if provided in test data
				if tt.headers["X-Vault-Namespace"] != "" && namespace != tt.headers["X-Vault-Namespace"] {
					t.Errorf("Expected VAULT_NAMESPACE %s, got %s", tt.headers["X-Vault-Namespace"], namespace)
				}
				if tt.envVars["VAULT_NAMESPACE"] != "" && namespace != tt.envVars["VAULT_NAMESPACE"] {
					t.Errorf("Expected VAULT_NAMESPACE %s, got %s", tt.envVars["VAULT_NAMESPACE"], namespace)
				}

				w.WriteHeader(http.StatusOK)
			})

			// Wrap with middleware
			middleware := VaultContextMiddleware(logger)
			handler := middleware(testHandler)

			// Create request
			req := httptest.NewRequest("GET", "/test", nil)

			// Add headers
			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			// Add query parameters
			q := req.URL.Query()
			for key, value := range tt.queryParams {
				q.Add(key, value)
			}
			req.URL.RawQuery = q.Encode()

			// Execute request
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != tt.expectedResponse {
				t.Errorf("Expected status %v, got %d", tt.expectedResponse, rr.Code)
			}
		})
	}
}

func TestLoadCORSConfigFromEnv(t *testing.T) {
	// Save original env vars to restore later
	origOrigins := os.Getenv("MCP_ALLOWED_ORIGINS")
	origMode := os.Getenv("MCP_CORS_MODE")
	defer func() {
		os.Setenv("MCP_ALLOWED_ORIGINS", origOrigins)
		os.Setenv("MCP_CORS_MODE", origMode)
	}()

	// Test case: When environment variables are not set, default values should be used
	// Default mode should be "strict" and allowed origins should be empty
	os.Unsetenv("MCP_ALLOWED_ORIGINS")
	os.Unsetenv("MCP_CORS_MODE")
	config := LoadCORSConfigFromEnv()
	assert.Equal(t, "strict", config.Mode)
	assert.Empty(t, config.AllowedOrigins)

	// Test case: When environment variables are set, their values should be used
	// Mode should be "development" and allowed origins should contain the specified values
	os.Setenv("MCP_ALLOWED_ORIGINS", "https://example.com, https://test.com")
	os.Setenv("MCP_CORS_MODE", "development")
	config = LoadCORSConfigFromEnv()
	assert.Equal(t, "development", config.Mode)
	assert.Equal(t, []string{"https://example.com", "https://test.com"}, config.AllowedOrigins)
}

// TestSecurityHandler tests the HTTP handler that applies CORS validation logic
// to incoming requests. This test verifies the complete request handling flow,
// including origin validation and response generation.
func TestSecurityHandler(t *testing.T) {
	logger := log.New()
	logger.SetLevel(log.ErrorLevel) // Reduce noise in tests

	// Create a mock handler that always succeeds
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	})

	tests := []struct {
		name           string
		origin         string
		allowedOrigins []string
		mode           string
		expectedStatus int
		expectedHeader bool
	}{
		// Strict mode tests
		{
			name:           "strict mode - allowed origin",
			origin:         "https://example.com",
			allowedOrigins: []string{"https://example.com"},
			mode:           "strict",
			expectedStatus: http.StatusOK,
			expectedHeader: true, // CORS headers should be set for allowed origins
		},
		{
			name:           "strict mode - disallowed origin",
			origin:         "https://evil.com",
			allowedOrigins: []string{"https://example.com"},
			mode:           "strict",
			expectedStatus: http.StatusForbidden,
			expectedHeader: false, // No CORS headers for rejected requests
		},
		{
			name:           "strict mode - localhost origin",
			origin:         "http://localhost:3000",
			allowedOrigins: []string{"https://example.com"},
			mode:           "strict",
			expectedStatus: http.StatusForbidden, // Localhost is not automatically allowed in strict mode
			expectedHeader: false,
		},
		{
			name:           "strict mode - no origin header",
			origin:         "", // No origin header
			allowedOrigins: []string{"https://example.com"},
			mode:           "strict",
			expectedStatus: http.StatusOK, // Requests without Origin headers bypass CORS checks
			expectedHeader: false,         // No CORS headers when no Origin header is present
		},

		// Development mode tests
		{
			name:           "development mode - localhost allowed",
			origin:         "http://localhost:3000",
			allowedOrigins: []string{},
			mode:           "development",
			expectedStatus: http.StatusOK, // Localhost is automatically allowed in development mode
			expectedHeader: true,          // CORS headers should be set
		},
		{
			name:           "development mode - 127.0.0.1 allowed",
			origin:         "http://127.0.0.1:3000",
			allowedOrigins: []string{},
			mode:           "development",
			expectedStatus: http.StatusOK, // IPv4 localhost is automatically allowed in development mode
			expectedHeader: true,
		},
		{
			name:           "development mode - allowed origin",
			origin:         "https://example.com",
			allowedOrigins: []string{"https://example.com"},
			mode:           "development",
			expectedStatus: http.StatusOK, // Explicitly allowed origins are still allowed in development mode
			expectedHeader: true,
		},
		{
			name:           "development mode - disallowed origin",
			origin:         "https://evil.com",
			allowedOrigins: []string{"https://example.com"},
			mode:           "development",
			expectedStatus: http.StatusForbidden, // Non-localhost, non-allowed origins are still rejected
			expectedHeader: false,
		},
		{
			name:           "development mode - no origin header",
			origin:         "", // No origin header
			allowedOrigins: []string{"https://example.com"},
			mode:           "development",
			expectedStatus: http.StatusOK, // Requests without Origin headers bypass CORS checks
			expectedHeader: false,
		},

		// Disabled mode tests
		{
			name:           "disabled mode - any origin allowed",
			origin:         "https://evil.com",
			allowedOrigins: []string{"https://example.com"},
			mode:           "disabled",
			expectedStatus: http.StatusOK, // All origins are allowed in disabled mode
			expectedHeader: true,
		},
		{
			name:           "disabled mode - localhost allowed",
			origin:         "http://localhost:3000",
			allowedOrigins: []string{},
			mode:           "disabled",
			expectedStatus: http.StatusOK, // Localhost is allowed in disabled mode (like any origin)
			expectedHeader: true,
		},
		{
			name:           "disabled mode - no origin header",
			origin:         "", // No origin header
			allowedOrigins: []string{},
			mode:           "disabled",
			expectedStatus: http.StatusOK, // Requests without Origin headers are allowed
			expectedHeader: false,         // No CORS headers when no Origin header is present
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := NewSecurityHandler(mockHandler, tt.allowedOrigins, tt.mode, logger)

			req := httptest.NewRequest("GET", "/mcp", nil)
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			assert.Equal(t, tt.expectedStatus, rr.Code)

			if tt.expectedHeader {
				assert.Equal(t, tt.origin, rr.Header().Get("Access-Control-Allow-Origin"))
				assert.NotEmpty(t, rr.Header().Get("Access-Control-Allow-Methods"))
			} else if tt.expectedStatus == http.StatusOK {
				assert.Empty(t, rr.Header().Get("Access-Control-Allow-Origin"))
			}
		})
	}
}

func TestLoggingMiddleware(t *testing.T) {
	logger := log.New()
	logger.SetOutput(os.Stdout)

	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := LoggingMiddleware(logger)
	handler := middleware(testHandler)

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("User-Agent", "test-agent")
	rr := httptest.NewRecorder()

	// This test mainly ensures the middleware doesn't break the request flow
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}
}

// TestIsOriginAllowed tests the core function that determines if an origin is allowed
// based on the CORS configuration. This function is called by the security handler
// when processing requests with Origin headers.
func TestIsOriginAllowed(t *testing.T) {
	tests := []struct {
		name           string
		origin         string
		allowedOrigins []string
		mode           string
		expected       bool
	}{
		// Strict mode tests
		{
			name:           "strict mode - allowed origin",
			origin:         "https://example.com",
			allowedOrigins: []string{"https://example.com", "https://test.com"},
			mode:           "strict",
			expected:       true,
		},
		{
			name:           "strict mode - disallowed origin",
			origin:         "https://evil.com",
			allowedOrigins: []string{"https://example.com", "https://test.com"},
			mode:           "strict",
			expected:       false,
		},
		{
			name:           "strict mode - localhost origin",
			origin:         "http://localhost:3000",
			allowedOrigins: []string{"https://example.com"},
			mode:           "strict",
			expected:       false, // Localhost is not automatically allowed in strict mode
		},
		// Note: The "no origin header" case cannot be directly tested here since
		// isOriginAllowed requires an origin parameter. This behavior is tested
		// in TestSecurityHandler instead.

		// Development mode tests
		{
			name:           "development mode - localhost allowed",
			origin:         "http://localhost:3000",
			allowedOrigins: []string{"https://example.com"},
			mode:           "development",
			expected:       true, // Localhost is automatically allowed in development mode
		},
		{
			name:           "development mode - 127.0.0.1 allowed",
			origin:         "http://127.0.0.1:3000",
			allowedOrigins: []string{"https://example.com"},
			mode:           "development",
			expected:       true, // IPv4 localhost is automatically allowed in development mode
		},
		{
			name:           "development mode - ::1 allowed",
			origin:         "http://[::1]:3000",
			allowedOrigins: []string{"https://example.com"},
			mode:           "development",
			expected:       true, // IPv6 localhost is automatically allowed in development mode
		},
		{
			name:           "development mode - allowed origin",
			origin:         "https://example.com",
			allowedOrigins: []string{"https://example.com"},
			mode:           "development",
			expected:       true, // Explicitly allowed origins are still allowed in development mode
		},
		{
			name:           "development mode - disallowed origin",
			origin:         "https://evil.com",
			allowedOrigins: []string{"https://example.com"},
			mode:           "development",
			expected:       false, // Non-localhost, non-allowed origins are still rejected in development mode
		},

		// Disabled mode tests
		{
			name:           "disabled mode - any origin allowed",
			origin:         "https://evil.com",
			allowedOrigins: []string{"https://example.com"},
			mode:           "disabled",
			expected:       true, // All origins are allowed in disabled mode
		},
		{
			name:           "disabled mode - localhost allowed",
			origin:         "http://localhost:3000",
			allowedOrigins: []string{},
			mode:           "disabled",
			expected:       true, // Localhost is allowed in disabled mode (like any origin)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isOriginAllowed(tt.origin, tt.allowedOrigins, tt.mode)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestVaultContextMiddleware_SecurityLogging tests that the middleware properly logs
// security-related events without exposing sensitive information
func TestVaultContextMiddleware_SecurityLogging(t *testing.T) {
	// Create a custom logger that captures log output
	logger := log.New()
	logger.SetLevel(log.DebugLevel)

	// Create a mock handler
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := VaultContextMiddleware(logger)
	handler := middleware(mockHandler)

	t.Run("token provided via header is logged without exposing value", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/mcp", nil)
		req.Header.Set(VaultToken, "secret-token")

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		// Note: In a real test, you'd capture the log output and verify it contains
		// "Vault token provided via request context" but doesn't contain "secret-token"
	})

	t.Run("address provided via header is logged", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/mcp", nil)
		req.Header.Set(VaultAddress, "https://custom.vault.example.com:8200")

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		// Note: In a real test, you'd capture the log output and verify it contains
		// "Vault address configured via request context"
	})

	t.Run("namespace provided via header is logged", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/mcp", nil)
		req.Header.Set(VaultHeaderNamespace, "test-namespace")

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		// Note: In a real test, you'd capture the log output and verify it contains
		// "Vault namespace configured via request context"
	})
}

// TestVaultContextMiddleware_EdgeCases tests edge cases and error conditions
func TestVaultContextMiddleware_EdgeCases(t *testing.T) {
	logger := log.New()
	logger.SetLevel(log.ErrorLevel)

	t.Run("nil logger should not panic", func(t *testing.T) {
		// This tests that the middleware handles a nil logger gracefully
		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		// Create middleware with nil logger - this should not panic
		assert.NotPanics(t, func() {
			middleware := VaultContextMiddleware(nil)
			handler := middleware(mockHandler)

			req := httptest.NewRequest("GET", "/mcp", nil)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
		})
	})

	t.Run("malformed query parameters are handled gracefully", func(t *testing.T) {
		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := VaultContextMiddleware(logger)
		handler := middleware(mockHandler)

		// Create request with malformed query string
		req := httptest.NewRequest("GET", "/mcp?%invalid", nil)

		rr := httptest.NewRecorder()
		// This should not panic even with malformed query parameters
		assert.NotPanics(t, func() {
			handler.ServeHTTP(rr, req)
		})
	})

	t.Run("vault token in query parameters is rejected for security", func(t *testing.T) {
		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middleware := VaultContextMiddleware(logger)
		handler := middleware(mockHandler)

		// Create request with VAULT_TOKEN in query parameters (should be rejected)
		req := httptest.NewRequest("GET", "/mcp?VAULT_TOKEN=secret-token", nil)

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		// Should return 400 Bad Request for security reasons
		assert.Equal(t, http.StatusBadRequest, rr.Code)
		assert.Contains(t, rr.Body.String(), "Vault token should not be provided in query parameters")
	})

	t.Run("very long header values are handled", func(t *testing.T) {
		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			val := ctx.Value(contextKey(VaultAddress))
			assert.NotNil(t, val)
			w.WriteHeader(http.StatusOK)
		})

		middleware := VaultContextMiddleware(logger)
		handler := middleware(mockHandler)

		// Create a very long Vault address value
		longAddress := "https://" + strings.Repeat("a", 1000) + ".vault.example.com:8200"

		req := httptest.NewRequest("GET", "/mcp", nil)
		req.Header.Set(VaultAddress, longAddress)

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("context values are properly set for all vault headers", func(t *testing.T) {
		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// Check that all Vault-related context values are set
			addr := ctx.Value(contextKey(VaultAddress))
			token := ctx.Value(contextKey(VaultToken))
			skipVerify := ctx.Value(contextKey(VaultSkipTLSVerify))
			namespace := ctx.Value(contextKey(VaultNamespace))

			assert.Equal(t, "https://vault.example.com:8200", addr)
			assert.Equal(t, "test-token", token)
			assert.Equal(t, "true", skipVerify)
			assert.Equal(t, "test-namespace", namespace)

			w.WriteHeader(http.StatusOK)
		})

		middleware := VaultContextMiddleware(logger)
		handler := middleware(mockHandler)

		req := httptest.NewRequest("GET", "/mcp", nil)
		req.Header.Set(VaultAddress, "https://vault.example.com:8200")
		req.Header.Set(VaultToken, "test-token")
		req.Header.Set(VaultSkipTLSVerify, "true")
		req.Header.Set(VaultHeaderNamespace, "test-namespace")

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("environment variables are used as fallback", func(t *testing.T) {
		// Set environment variables
		os.Setenv(VaultAddress, "https://env-vault.example.com:8200")
		os.Setenv(VaultToken, "env-token")
		os.Setenv(VaultNamespace, "env-namespace")
		defer func() {
			os.Unsetenv(VaultAddress)
			os.Unsetenv(VaultToken)
			os.Unsetenv(VaultNamespace)
		}()

		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			addr := ctx.Value(contextKey(VaultAddress))
			token := ctx.Value(contextKey(VaultToken))
			namespace := ctx.Value(contextKey(VaultNamespace))

			assert.Equal(t, "https://env-vault.example.com:8200", addr)
			assert.Equal(t, "env-token", token)
			assert.Equal(t, "env-namespace", namespace)

			w.WriteHeader(http.StatusOK)
		})

		middleware := VaultContextMiddleware(logger)
		handler := middleware(mockHandler)

		// Request without headers should use environment variables
		req := httptest.NewRequest("GET", "/mcp", nil)

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})
}
