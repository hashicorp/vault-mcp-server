// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"net/http"
	"net/textproto"

	log "github.com/sirupsen/logrus"
)

// VaultContextMiddleware adds Vault-related header values to the request context
// This middleware extracts Vault configuration from HTTP headers, query parameters,
// or environment variables and adds them to the request context for use by MCP tools
func VaultContextMiddleware(logger *log.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requiredHeaders := []string{VaultAddress, VaultToken, VaultSkipTLSVerify}
			ctx := r.Context()
			/*
				if !r.URL.Query().Has("Authorization") || r.Header.Get("Authorization") == "" {
					http.Error(w, "Unauthorized: Please provide valid credentials", http.StatusUnauthorized)
					return
				}
			*/
			for _, header := range requiredHeaders {
				// Priority order: HTTP header -> Query parameter -> Environment variable
				headerValue := r.Header.Get(textproto.CanonicalMIMEHeaderKey(header))

				if headerValue == "" {
					headerValue = r.URL.Query().Get(header)

					// Explicitly disallow VaultToken in query parameters for security reasons
					if header == VaultToken && headerValue != "" {
						logger.Info(fmt.Sprintf("Vault token was provided in query parameters by client %v, termiating request", r.RemoteAddr))
						http.Error(w, "Vault token should not be provided in query parameters for security reasons, use the vault_token header", http.StatusBadRequest)
						return
					}
				}

				if headerValue == "" {
					headerValue = getEnv(header, "")
				}

				// Add to context using the header name as key
				ctx = context.WithValue(ctx, contextKey(header), headerValue)

				// Log the source of the configuration (without exposing sensitive values)
				if header == VaultToken && headerValue != "" {
					logger.Debug("Vault token provided via request context")
				} else if header == VaultAddress && headerValue != "" {
					logger.Debug("Vault address configured via request context")
				}
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
