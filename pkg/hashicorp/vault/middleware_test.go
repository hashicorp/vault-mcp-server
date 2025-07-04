// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	log "github.com/sirupsen/logrus"
)

func TestVaultContextMiddleware(t *testing.T) {
	logger := log.New()
	logger.SetOutput(os.Stdout)

	tests := []struct {
		name           string
		headers        map[string]string
		queryParams    map[string]string
		envVars        map[string]string
		expectedAddr   string
		expectedToken  string
	}{
		{
			name: "headers take precedence",
			headers: map[string]string{
				"VAULT_ADDR":  "http://header-vault:8200",
				"VAULT_TOKEN": "header-token",
			},
			queryParams: map[string]string{
				"VAULT_ADDR":  "http://query-vault:8200",
				"VAULT_TOKEN": "query-token",
			},
			expectedAddr:  "http://header-vault:8200",
			expectedToken: "header-token",
		},
		{
			name: "query params when no headers",
			queryParams: map[string]string{
				"VAULT_ADDR":  "http://query-vault:8200",
				"VAULT_TOKEN": "query-token",
			},
			expectedAddr:  "http://query-vault:8200",
			expectedToken: "query-token",
		},
		{
			name: "environment variables as fallback",
			envVars: map[string]string{
				"VAULT_ADDR":  "http://env-vault:8200",
				"VAULT_TOKEN": "env-token",
			},
			expectedAddr:  "http://env-vault:8200",
			expectedToken: "env-token",
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
				
				addr, ok := ctx.Value(contextKey(VaultAddressHeader)).(string)
				if !ok {
					addr = ""
				}
				
				token, ok := ctx.Value(contextKey(VaultTokenHeader)).(string)
				if !ok {
					token = ""
				}

				if addr != tt.expectedAddr {
					t.Errorf("Expected VAULT_ADDR %s, got %s", tt.expectedAddr, addr)
				}
				
				if token != tt.expectedToken {
					t.Errorf("Expected VAULT_TOKEN %s, got %s", tt.expectedToken, token)
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

			if rr.Code != http.StatusOK {
				t.Errorf("Expected status 200, got %d", rr.Code)
			}
		})
	}
}

func TestCORSMiddleware(t *testing.T) {
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := CORSMiddleware()
	handler := middleware(testHandler)

	t.Run("adds CORS headers", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		rr := httptest.NewRecorder()
		
		handler.ServeHTTP(rr, req)

		expectedHeaders := map[string]string{
			"Access-Control-Allow-Origin":  "*",
			"Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
			"Access-Control-Allow-Headers": "Content-Type, Authorization, VAULT_ADDR, VAULT_TOKEN",
		}

		for header, expectedValue := range expectedHeaders {
			if got := rr.Header().Get(header); got != expectedValue {
				t.Errorf("Expected %s header to be %s, got %s", header, expectedValue, got)
			}
		}
	})

	t.Run("handles OPTIONS request", func(t *testing.T) {
		req := httptest.NewRequest("OPTIONS", "/test", nil)
		rr := httptest.NewRecorder()
		
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Expected status 200 for OPTIONS request, got %d", rr.Code)
		}
	})
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
