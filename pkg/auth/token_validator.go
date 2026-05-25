// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package auth

import (
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	log "github.com/sirupsen/logrus"
)

// TokenValidator validates and refreshes OIDC tokens
type TokenValidator struct {
	oidcClient *OIDCClient
	logger     *log.Logger
}

// NewTokenValidator creates a new token validator
func NewTokenValidator(oidcClient *OIDCClient, logger *log.Logger) *TokenValidator {
	return &TokenValidator{
		oidcClient: oidcClient,
		logger:     logger,
	}
}

// ValidateTokenOffline validates a JWT token offline (signature and expiry)
// Does not make network calls to the IdP
func (tv *TokenValidator) ValidateTokenOffline(tokenString string) error {
	if tokenString == "" {
		return fmt.Errorf("token is empty")
	}

	// Parse token without verification to check expiry
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return fmt.Errorf("invalid token claims")
	}

	// Check expiration
	if exp, ok := claims["exp"].(float64); ok {
		expiryTime := time.Unix(int64(exp), 0)
		if time.Now().After(expiryTime) {
			return ErrTokenExpired
		}
	} else {
		return fmt.Errorf("token missing exp claim")
	}

	tv.logger.Debug("Token validated offline successfully")
	return nil
}

// ShouldRefresh checks if a token should be refreshed based on expiry time
// Returns true if token expires within the configured threshold
func (tv *TokenValidator) ShouldRefresh(expiresAt time.Time, threshold time.Duration) bool {
	timeUntilExpiry := time.Until(expiresAt)
	shouldRefresh := timeUntilExpiry <= threshold && timeUntilExpiry > 0

	tv.logger.WithFields(log.Fields{
		"expires_at":        expiresAt.Format(time.RFC3339),
		"time_until_expiry": timeUntilExpiry,
		"threshold":         threshold,
		"should_refresh":    shouldRefresh,
	}).Debug("Checked if token should be refreshed")

	return shouldRefresh
}

// IsTokenExpired checks if a token is expired
func (tv *TokenValidator) IsTokenExpired(expiresAt time.Time) bool {
	isExpired := time.Now().After(expiresAt)
	tv.logger.WithFields(log.Fields{
		"expires_at": expiresAt.Format(time.RFC3339),
		"is_expired": isExpired,
	}).Debug("Checked if token is expired")
	return isExpired
}

// ValidateCache validates a token cache
func (tv *TokenValidator) ValidateCache(cache *TokenCache) error {
	if cache == nil {
		return fmt.Errorf("cache is nil")
	}

	if cache.AccessToken == "" {
		return fmt.Errorf("access token is missing")
	}

	if cache.IsExpired() {
		return ErrTokenExpired
	}

	// Optionally validate token structure
	if err := tv.ValidateTokenOffline(cache.AccessToken); err != nil {
		return fmt.Errorf("access token validation failed: %w", err)
	}

	tv.logger.Debug("Token cache validated successfully")
	return nil
}

// ValidateAndExtractClaims validates a token and extracts claims
func (tv *TokenValidator) ValidateAndExtractClaims(tokenString string) (jwt.MapClaims, error) {
	if tokenString == "" {
		return nil, fmt.Errorf("token is empty")
	}

	// Parse token without verification to extract claims
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}

	// Validate expiration
	if exp, ok := claims["exp"].(float64); ok {
		expiryTime := time.Unix(int64(exp), 0)
		if time.Now().After(expiryTime) {
			return nil, ErrTokenExpired
		}
	}

	// Validate issuer if configured
	if tv.oidcClient != nil && tv.oidcClient.config.Issuer != "" {
		if iss, ok := claims["iss"].(string); ok {
			// Normalize issuer (with and without trailing slash)
			configIssuer := strings.TrimSuffix(tv.oidcClient.config.Issuer, "/")
			tokenIssuer := strings.TrimSuffix(iss, "/")
			if tokenIssuer != configIssuer {
				return nil, ErrInvalidIssuer
			}
		} else {
			return nil, fmt.Errorf("token missing iss claim")
		}
	}

	tv.logger.WithFields(log.Fields{
		"sub": claims["sub"],
		"iss": claims["iss"],
	}).Debug("Token validated and claims extracted")

	return claims, nil
}

// GetExpiryTime extracts the expiry time from a JWT token
func GetExpiryTime(tokenString string) (time.Time, error) {
	if tokenString == "" {
		return time.Time{}, fmt.Errorf("token is empty")
	}

	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return time.Time{}, fmt.Errorf("invalid token claims")
	}

	if exp, ok := claims["exp"].(float64); ok {
		return time.Unix(int64(exp), 0), nil
	}

	return time.Time{}, fmt.Errorf("token missing exp claim")
}
