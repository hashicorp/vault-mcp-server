// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package auth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	log "github.com/sirupsen/logrus"
)

var (
	ErrInvalidToken     = errors.New("invalid token")
	ErrTokenExpired     = errors.New("token expired")
	ErrInvalidAudience  = errors.New("invalid audience")
	ErrInvalidIssuer    = errors.New("invalid issuer")
	ErrMissingScopes    = errors.New("missing required scopes")
	ErrInvalidSignature = errors.New("invalid token signature")
	ErrJWKSFetch        = errors.New("failed to fetch JWKS")
)

// ProviderType represents the OAuth provider type
type ProviderType string

const (
	ProviderAuth0 ProviderType = "auth0"
	ProviderOkta  ProviderType = "okta"
)

// OAuthConfig holds OAuth provider configuration
type OAuthConfig struct {
	Provider       ProviderType // OAuth provider (auth0, okta)
	Domain         string       // Provider domain (e.g., "your-tenant.us.auth0.com" or "dev-12345.okta.com")
	Audience       string       // API identifier
	RequiredScopes []string     // Required scopes for MCP access
	Issuer         string       // Token issuer (auto-detected if not provided)
	AuthServerID   string       // Okta authorization server ID (default: "default")
	Enabled        bool         // Whether auth is enabled
}

// Auth0Config is an alias for backward compatibility
type Auth0Config = OAuthConfig

// JWKS represents JSON Web Key Set
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK represents a JSON Web Key
type JWK struct {
	Kty string   `json:"kty"`
	Kid string   `json:"kid"`
	Use string   `json:"use"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X5c []string `json:"x5c"`
}

// OAuthValidator validates OAuth JWT tokens (Auth0, Okta, etc.)
type OAuthValidator struct {
	config      OAuthConfig
	jwksURL     string
	jwksCache   map[string]*rsa.PublicKey
	jwksCacheMu sync.RWMutex
	cacheExpiry time.Time
	httpClient  *http.Client
	logger      *log.Logger
}

// Auth0Validator is an alias for backward compatibility
type Auth0Validator = OAuthValidator

// NewOAuthValidator creates a new OAuth token validator
func NewOAuthValidator(config OAuthConfig, logger *log.Logger) *OAuthValidator {
	// Normalize domain to include https://
	if !strings.HasPrefix(config.Domain, "https://") {
		config.Domain = "https://" + config.Domain
	}

	// Build JWKS URL and issuer based on provider
	var jwksURL, issuer string

	switch config.Provider {
	case ProviderOkta:
		// Okta uses /oauth2/{authServerID}/v1/keys
		authServerID := config.AuthServerID
		if authServerID == "" {
			authServerID = "default"
		}
		jwksURL = fmt.Sprintf("%s/oauth2/%s/v1/keys", config.Domain, authServerID)
		if config.Issuer == "" {
			issuer = fmt.Sprintf("%s/oauth2/%s", config.Domain, authServerID)
		} else {
			issuer = config.Issuer
		}
	case ProviderAuth0:
		fallthrough
	default:
		// Auth0 uses /.well-known/jwks.json
		jwksURL = config.Domain + "/.well-known/jwks.json"
		if config.Issuer == "" {
			issuer = config.Domain + "/"
		} else {
			issuer = config.Issuer
		}
	}

	config.Issuer = issuer

	return &OAuthValidator{
		config:     config,
		jwksURL:    jwksURL,
		jwksCache:  make(map[string]*rsa.PublicKey),
		httpClient: &http.Client{Timeout: 10 * time.Second},
		logger:     logger,
	}
}

// NewAuth0Validator creates a new Auth0 token validator (backward compatibility)
func NewAuth0Validator(config Auth0Config, logger *log.Logger) *Auth0Validator {
	if config.Provider == "" {
		config.Provider = ProviderAuth0
	}
	return NewOAuthValidator(config, logger)
}

// ValidateToken validates an OAuth JWT token
func (v *OAuthValidator) ValidateToken(ctx context.Context, tokenString string) (*jwt.Token, error) {
	// Parse token without validation first to get the kid
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Get kid from token header
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, errors.New("kid not found in token header")
		}

		// Get public key for this kid
		publicKey, err := v.getPublicKey(ctx, kid)
		if err != nil {
			return nil, fmt.Errorf("failed to get public key: %w", err)
		}

		return publicKey, nil
	})

	if err != nil {
		v.logger.WithError(err).Debug("Token validation failed")
		return nil, ErrInvalidToken
	}

	if !token.Valid {
		return nil, ErrInvalidToken
	}

	// Validate claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, ErrInvalidToken
	}

	// Verify issuer
	if err := v.verifyIssuer(claims); err != nil {
		return nil, err
	}

	// Verify audience
	if err := v.verifyAudience(claims); err != nil {
		return nil, err
	}

	// Verify expiration
	if err := v.verifyExpiration(claims); err != nil {
		return nil, err
	}

	// Verify scopes if required
	if len(v.config.RequiredScopes) > 0 {
		if err := v.verifyScopes(claims); err != nil {
			return nil, err
		}
	}

	return token, nil
}

// getPublicKey retrieves the public key for the given kid
func (v *Auth0Validator) getPublicKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	// Check cache first
	v.jwksCacheMu.RLock()
	if publicKey, ok := v.jwksCache[kid]; ok && time.Now().Before(v.cacheExpiry) {
		v.jwksCacheMu.RUnlock()
		return publicKey, nil
	}
	v.jwksCacheMu.RUnlock()

	// Fetch JWKS
	if err := v.refreshJWKS(ctx); err != nil {
		return nil, err
	}

	// Try cache again
	v.jwksCacheMu.RLock()
	defer v.jwksCacheMu.RUnlock()

	publicKey, ok := v.jwksCache[kid]
	if !ok {
		return nil, fmt.Errorf("public key not found for kid: %s", kid)
	}

	return publicKey, nil
}

// refreshJWKS fetches and caches the JWKS
func (v *Auth0Validator) refreshJWKS(ctx context.Context) error {
	v.jwksCacheMu.Lock()
	defer v.jwksCacheMu.Unlock()

	// Check if another goroutine already refreshed
	if time.Now().Before(v.cacheExpiry) {
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURL, nil)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrJWKSFetch, err)
	}

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrJWKSFetch, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: status code %d", ErrJWKSFetch, resp.StatusCode)
	}

	var jwks JWKS
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return fmt.Errorf("%w: failed to decode JWKS: %v", ErrJWKSFetch, err)
	}

	// Clear old cache
	v.jwksCache = make(map[string]*rsa.PublicKey)

	// Parse and cache public keys
	for _, key := range jwks.Keys {
		if key.Kty != "RSA" {
			continue
		}

		publicKey, err := v.parseRSAPublicKey(key)
		if err != nil {
			v.logger.WithError(err).Warnf("Failed to parse public key for kid %s", key.Kid)
			continue
		}

		v.jwksCache[key.Kid] = publicKey
	}

	// Set cache expiry (1 hour)
	v.cacheExpiry = time.Now().Add(1 * time.Hour)

	v.logger.Debugf("Refreshed JWKS cache with %d keys", len(v.jwksCache))

	return nil
}

// parseRSAPublicKey parses an RSA public key from JWK
func (v *Auth0Validator) parseRSAPublicKey(key JWK) (*rsa.PublicKey, error) {
	// Decode modulus
	nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode modulus: %w", err)
	}

	// Decode exponent
	eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode exponent: %w", err)
	}

	// Convert to big integers
	n := new(big.Int).SetBytes(nBytes)

	// Convert exponent bytes to int
	var e int
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}

	return &rsa.PublicKey{
		N: n,
		E: e,
	}, nil
}

// verifyIssuer verifies the token issuer
func (v *Auth0Validator) verifyIssuer(claims jwt.MapClaims) error {
	iss, ok := claims["iss"].(string)
	if !ok {
		return ErrInvalidIssuer
	}

	if iss != v.config.Issuer {
		v.logger.Debugf("Invalid issuer: expected %s, got %s", v.config.Issuer, iss)
		return ErrInvalidIssuer
	}

	return nil
}

// verifyAudience verifies the token audience
func (v *Auth0Validator) verifyAudience(claims jwt.MapClaims) error {
	aud, ok := claims["aud"]
	if !ok {
		return ErrInvalidAudience
	}

	// Audience can be a string or array of strings
	switch audVal := aud.(type) {
	case string:
		if audVal != v.config.Audience {
			v.logger.Debugf("Invalid audience: expected %s, got %s", v.config.Audience, audVal)
			return ErrInvalidAudience
		}
	case []interface{}:
		found := false
		for _, a := range audVal {
			if audStr, ok := a.(string); ok && audStr == v.config.Audience {
				found = true
				break
			}
		}
		if !found {
			return ErrInvalidAudience
		}
	default:
		return ErrInvalidAudience
	}

	return nil
}

// verifyExpiration verifies the token has not expired
func (v *Auth0Validator) verifyExpiration(claims jwt.MapClaims) error {
	exp, ok := claims["exp"].(float64)
	if !ok {
		return ErrTokenExpired
	}

	if time.Now().Unix() > int64(exp) {
		return ErrTokenExpired
	}

	return nil
}

// verifyScopes verifies the token has required scopes
func (v *Auth0Validator) verifyScopes(claims jwt.MapClaims) error {
	// Try different scope claim names used by various providers
	// - "scope": Auth0 standard
	// - "scp": Okta standard
	// - "permissions": Auth0 alternative
	var scopesInterface interface{}
	var ok bool

	for _, claimName := range []string{"scope", "scp", "permissions"} {
		scopesInterface, ok = claims[claimName]
		if ok {
			break
		}
	}

	if !ok {
		v.logger.Debug("No scope claim found (tried: scope, scp, permissions)")
		return ErrMissingScopes
	}

	var scopes []string
	switch scopeValue := scopesInterface.(type) {
	case string:
		// Space-separated scopes
		scopes = strings.Split(scopeValue, " ")
	case []interface{}:
		// Array of scopes
		for _, s := range scopeValue {
			if scopeStr, ok := s.(string); ok {
				scopes = append(scopes, scopeStr)
			}
		}
	default:
		v.logger.Debugf("Unexpected scope claim type: %T", scopesInterface)
		return ErrMissingScopes
	}

	// Check if all required scopes are present
	scopeMap := make(map[string]bool)
	for _, scope := range scopes {
		scopeMap[scope] = true
	}

	v.logger.Debugf("Token scopes: %v", scopes)

	for _, required := range v.config.RequiredScopes {
		if !scopeMap[required] {
			v.logger.Debugf("Missing required scope: %s", required)
			return ErrMissingScopes
		}
	}

	return nil
}

// GetTokenClaims extracts claims from a validated token
func GetTokenClaims(token *jwt.Token) (jwt.MapClaims, error) {
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid token claims")
	}
	return claims, nil
}
