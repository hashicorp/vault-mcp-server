// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	log "github.com/sirupsen/logrus"
)

func TestMetadataHandler(t *testing.T) {
	logger := log.New()
	logger.SetLevel(log.ErrorLevel)

	config := Auth0Config{
		Domain:         "test.auth0.com",
		Audience:       "https://api.test.com",
		RequiredScopes: []string{"mcp:tools", "mcp:resources"},
		Enabled:        true,
	}

	handler := NewMetadataHandler(config, "http://localhost:8080/mcp", logger)

	t.Run("GET returns metadata", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		var metadata ProtectedResourceMetadata
		if err := json.NewDecoder(w.Body).Decode(&metadata); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		if metadata.Resource != "http://localhost:8080/mcp" {
			t.Errorf("Expected resource http://localhost:8080/mcp, got %s", metadata.Resource)
		}

		if len(metadata.AuthorizationServers) == 0 {
			t.Error("Expected authorization servers to be set")
		}

		expectedDomain := "test.auth0.com"
		if metadata.AuthorizationServers[0] != expectedDomain {
			t.Errorf("Expected authorization server %s, got %s", expectedDomain, metadata.AuthorizationServers[0])
		}

		if len(metadata.ScopesSupported) != 2 {
			t.Errorf("Expected 2 scopes, got %d", len(metadata.ScopesSupported))
		}
	})

	t.Run("POST returns 405", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/.well-known/oauth-protected-resource", nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("Expected status 405, got %d", w.Code)
		}
	})
}

func TestAuthMiddleware_Disabled(t *testing.T) {
	logger := log.New()
	logger.SetLevel(log.ErrorLevel)

	config := Auth0Config{
		Enabled: false,
	}

	middleware := NewAuthMiddleware(config, "http://localhost:8080/.well-known/oauth-protected-resource", logger)

	called := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	wrappedHandler := middleware.Middleware(handler)

	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	w := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(w, req)

	if !called {
		t.Error("Expected handler to be called when auth is disabled")
	}

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestAuthMiddleware_ExemptPaths(t *testing.T) {
	logger := log.New()
	logger.SetLevel(log.ErrorLevel)

	config := Auth0Config{
		Enabled:  true,
		Domain:   "test.auth0.com",
		Audience: "https://api.test.com",
	}

	middleware := NewAuthMiddleware(config, "http://localhost:8080/.well-known/oauth-protected-resource", logger)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrappedHandler := middleware.Middleware(handler)

	exemptPaths := []string{
		"/.well-known/oauth-protected-resource",
		"/.well-known/openid-configuration",
		"/health",
	}

	for _, path := range exemptPaths {
		t.Run("Exempt: "+path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			w := httptest.NewRecorder()

			wrappedHandler.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("Expected status 200 for exempt path %s, got %d", path, w.Code)
			}
		})
	}
}

func TestAuthMiddleware_MissingToken(t *testing.T) {
	logger := log.New()
	logger.SetLevel(log.ErrorLevel)

	config := Auth0Config{
		Enabled:        true,
		Domain:         "test.auth0.com",
		Audience:       "https://api.test.com",
		RequiredScopes: []string{"mcp:tools"},
	}

	resourceMetadataURL := "http://localhost:8080/.well-known/oauth-protected-resource"
	middleware := NewAuthMiddleware(config, resourceMetadataURL, logger)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrappedHandler := middleware.Middleware(handler)

	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	w := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", w.Code)
	}

	authHeader := w.Header().Get("WWW-Authenticate")
	if authHeader == "" {
		t.Error("Expected WWW-Authenticate header to be set")
	}

	expectedHeader := `Bearer realm="mcp", resource_metadata="` + resourceMetadataURL + `", scope="mcp:tools"`
	if authHeader != expectedHeader {
		t.Errorf("Expected WWW-Authenticate header %q, got %q", expectedHeader, authHeader)
	}
}

func TestAuthMiddleware_InvalidTokenFormat(t *testing.T) {
	logger := log.New()
	logger.SetLevel(log.ErrorLevel)

	config := Auth0Config{
		Enabled:  true,
		Domain:   "test.auth0.com",
		Audience: "https://api.test.com",
	}

	middleware := NewAuthMiddleware(config, "http://localhost:8080/.well-known/oauth-protected-resource", logger)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrappedHandler := middleware.Middleware(handler)

	tests := []struct {
		name  string
		token string
	}{
		{"Missing Bearer prefix", "invalid-token"},
		{"Empty after Bearer", "Bearer "},
		{"Only Bearer", "Bearer"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
			req.Header.Set("Authorization", tt.token)
			w := httptest.NewRecorder()

			wrappedHandler.ServeHTTP(w, req)

			if w.Code != http.StatusUnauthorized {
				t.Errorf("Expected status 401 for %s, got %d", tt.name, w.Code)
			}
		})
	}
}
