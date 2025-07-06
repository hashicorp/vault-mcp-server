// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package middleware

import (
	"context"
	"net/http"

	"github.com/hashicorp/vault-mcp-server/pkg/vault"

	log "github.com/sirupsen/logrus"
)

// VaultContextMiddleware adds Vault-related header values to the request context
// This middleware extracts Vault configuration from HTTP headers, query parameters,
// or environment variables and adds them to the request context for use by MCP tools
// Note: VAULT_TOKEN is NOT extracted from query parameters for security reasons
func VaultContextMiddleware(logger *log.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// Handle VAULT_ADDR - can come from headers, query params, or env vars
			vaultAddr := r.Header.Get(vault.VaultAddressHeader)
			if vaultAddr == "" {
				vaultAddr = r.URL.Query().Get(vault.VaultAddressHeader)
			}
			if vaultAddr == "" {
				vaultAddr = vault.GetEnv(vault.VaultAddressHeader, "")
			}
			ctx = context.WithValue(ctx, vault.ContextKey(vault.VaultAddressHeader), vaultAddr)

			// Handle VAULT_TOKEN - can only come from headers or env vars (NOT query params for security)
			vaultToken := r.Header.Get(vault.VaultTokenHeader)
			if vaultToken == "" {
				vaultToken = vault.GetEnv(vault.VaultTokenHeader, "")
			}
			ctx = context.WithValue(ctx, vault.ContextKey(vault.VaultTokenHeader), vaultToken)

			// Log the source of the configuration (without exposing sensitive values)
			if vaultToken != "" {
				logger.Debug("Vault token provided via request context")
			}
			if vaultAddr != "" {
				logger.WithField("vault_addr", vaultAddr).Debug("Vault address configured")
			}

			// Call the next handler with the enriched context
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// LoggingMiddleware logs HTTP requests with structured logging
func LoggingMiddleware(logger *log.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logger.WithFields(log.Fields{
				"method":     r.Method,
				"path":       r.URL.Path,
				"remote_ip":  r.RemoteAddr,
				"user_agent": r.UserAgent(),
			}).Info("HTTP request received")

			next.ServeHTTP(w, r)
		})
	}
}

// CORSMiddleware adds CORS headers for cross-origin requests
func CORSMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, VAULT_ADDR, VAULT_TOKEN")

			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusOK)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
