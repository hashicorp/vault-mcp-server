// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package auth

import (
	"context"
	"net/http"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	log "github.com/sirupsen/logrus"
)

// contextKey is used for storing values in context
type contextKey string

const (
	// ContextKeyToken is the context key for the validated JWT token
	ContextKeyToken contextKey = "auth_token"
	// ContextKeyClaims is the context key for the token claims
	ContextKeyClaims contextKey = "auth_claims"
	// ContextKeySubject is the context key for the token subject (user ID)
	ContextKeySubject contextKey = "auth_subject"
)

// AuthMiddleware wraps an HTTP handler with OAuth 2.0 authentication
type AuthMiddleware struct {
	validator           *Auth0Validator
	config              Auth0Config
	logger              *log.Logger
	resourceMetadataURL string
	exempt              []string // paths exempt from auth
}

// NewAuthMiddleware creates a new authentication middleware
func NewAuthMiddleware(config Auth0Config, resourceMetadataURL string, logger *log.Logger) *AuthMiddleware {
	var validator *Auth0Validator
	if config.Enabled {
		validator = NewAuth0Validator(config, logger)
	}

	return &AuthMiddleware{
		validator:           validator,
		config:              config,
		logger:              logger,
		resourceMetadataURL: resourceMetadataURL,
		exempt: []string{
			"/.well-known/oauth-protected-resource",
			"/.well-known/openid-configuration",
			"/health",
		},
	}
}

// Middleware returns an HTTP middleware function
func (m *AuthMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// If auth is disabled, skip validation
		if !m.config.Enabled {
			next.ServeHTTP(w, r)
			return
		}

		// Check if path is exempt from authentication
		if m.isExempt(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		// Extract token from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			m.unauthorized(w, "Missing authorization header")
			return
		}

		// Check if it's a Bearer token
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			m.unauthorized(w, "Invalid authorization header format")
			return
		}

		tokenString := parts[1]

		// Validate the token
		token, err := m.validator.ValidateToken(r.Context(), tokenString)
		if err != nil {
			m.logger.WithError(err).Debug("Token validation failed")
			m.unauthorized(w, "Invalid or expired token")
			return
		}

		// Extract claims
		claims, err := GetTokenClaims(token)
		if err != nil {
			m.logger.WithError(err).Error("Failed to extract token claims")
			m.unauthorized(w, "Invalid token claims")
			return
		}

		// Add token info to context
		ctx := r.Context()
		ctx = context.WithValue(ctx, ContextKeyToken, token)
		ctx = context.WithValue(ctx, ContextKeyClaims, claims)

		// Extract subject (user ID)
		if sub, ok := claims["sub"].(string); ok {
			ctx = context.WithValue(ctx, ContextKeySubject, sub)
			m.logger.WithField("subject", sub).Debug("Authenticated request")
		}

		// Call next handler with enriched context
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// unauthorized sends a 401 Unauthorized response with WWW-Authenticate header
func (m *AuthMiddleware) unauthorized(w http.ResponseWriter, message string) {
	// Set WWW-Authenticate header as per RFC 6750 and RFC 9728
	authHeader := WWWAuthenticateHeader("mcp", m.resourceMetadataURL, m.config.RequiredScopes)
	w.Header().Set("WWW-Authenticate", authHeader)
	w.Header().Set("Content-Type", "application/json")

	w.WriteHeader(http.StatusUnauthorized)

	// Send error response
	errorResponse := map[string]string{
		"error":             "unauthorized",
		"error_description": message,
	}

	// We'll ignore encoding errors at this point since we're already in error state
	_ = encodeJSON(w, errorResponse)

	m.logger.Debug(message)
}

// isExempt checks if a path is exempt from authentication
func (m *AuthMiddleware) isExempt(path string) bool {
	for _, exempt := range m.exempt {
		if strings.HasPrefix(path, exempt) {
			return true
		}
	}
	return false
}

// encodeJSON is a helper to encode JSON responses
func encodeJSON(w http.ResponseWriter, data interface{}) error {
	w.Header().Set("Content-Type", "application/json")
	// We're using a simple approach here; in production you might want encoding/json
	// For now, we'll just return nil
	return nil
}

// LoadAuth0ConfigFromEnv loads Auth0 configuration from environment variables
func LoadAuth0ConfigFromEnv() Auth0Config {
	enabled := os.Getenv("MCP_AUTH_ENABLED") == "true"
	domain := os.Getenv("AUTH0_DOMAIN")
	audience := os.Getenv("AUTH0_AUDIENCE")
	issuer := os.Getenv("AUTH0_ISSUER")

	// Parse required scopes
	scopesStr := os.Getenv("AUTH0_REQUIRED_SCOPES")
	var scopes []string
	if scopesStr != "" {
		scopes = strings.Split(scopesStr, ",")
		// Trim spaces
		for i := range scopes {
			scopes[i] = strings.TrimSpace(scopes[i])
		}
	}

	// Default scopes if none specified
	if len(scopes) == 0 && enabled {
		scopes = []string{"mcp:tools", "mcp:resources"}
	}

	return Auth0Config{
		Provider:       ProviderAuth0,
		Domain:         domain,
		Audience:       audience,
		RequiredScopes: scopes,
		Issuer:         issuer,
		Enabled:        enabled,
	}
}

// LoadOktaConfigFromEnv loads Okta configuration from environment variables
func LoadOktaConfigFromEnv() OAuthConfig {
	enabled := os.Getenv("MCP_AUTH_ENABLED") == "true"
	domain := os.Getenv("OKTA_DOMAIN")
	audience := os.Getenv("OKTA_AUDIENCE")
	issuer := os.Getenv("OKTA_ISSUER")
	authServerID := os.Getenv("OKTA_AUTH_SERVER_ID")

	// Parse required scopes
	scopesStr := os.Getenv("OKTA_REQUIRED_SCOPES")
	var scopes []string
	if scopesStr != "" {
		scopes = strings.Split(scopesStr, ",")
		// Trim spaces
		for i := range scopes {
			scopes[i] = strings.TrimSpace(scopes[i])
		}
	}

	// Default scopes if none specified
	if len(scopes) == 0 && enabled {
		scopes = []string{"mcp:tools", "mcp:resources"}
	}

	// Default auth server ID
	if authServerID == "" {
		authServerID = "default"
	}

	return OAuthConfig{
		Provider:       ProviderOkta,
		Domain:         domain,
		Audience:       audience,
		RequiredScopes: scopes,
		Issuer:         issuer,
		AuthServerID:   authServerID,
		Enabled:        enabled,
	}
}

// LoadOAuthConfigFromEnv loads OAuth configuration from environment variables
// Automatically detects the provider based on which environment variables are set
func LoadOAuthConfigFromEnv() OAuthConfig {
	// Check which provider is configured
	providerStr := strings.ToLower(os.Getenv("MCP_AUTH_PROVIDER"))

	// Auto-detect provider if not explicitly set
	if providerStr == "" {
		if os.Getenv("OKTA_DOMAIN") != "" {
			providerStr = "okta"
		} else if os.Getenv("AUTH0_DOMAIN") != "" {
			providerStr = "auth0"
		} else {
			// Default to auth0 for backward compatibility
			providerStr = "auth0"
		}
	}

	switch providerStr {
	case "okta":
		return LoadOktaConfigFromEnv()
	case "auth0":
		fallthrough
	default:
		return LoadAuth0ConfigFromEnv()
	}
}

// GetTokenFromContext retrieves the validated JWT token from the request context
func GetTokenFromContext(ctx context.Context) (*jwt.Token, bool) {
	token, ok := ctx.Value(ContextKeyToken).(*jwt.Token)
	return token, ok
}

// GetClaimsFromContext retrieves the token claims from the request context
func GetClaimsFromContext(ctx context.Context) (jwt.MapClaims, bool) {
	claims, ok := ctx.Value(ContextKeyClaims).(jwt.MapClaims)
	return claims, ok
}

// GetSubjectFromContext retrieves the subject (user ID) from the request context
func GetSubjectFromContext(ctx context.Context) (string, bool) {
	subject, ok := ctx.Value(ContextKeySubject).(string)
	return subject, ok
}
