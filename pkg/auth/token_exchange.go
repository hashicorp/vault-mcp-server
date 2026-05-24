// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	log "github.com/sirupsen/logrus"
)

// RFC 8693 Token Exchange grant type and token types
const (
	GrantTypeTokenExchange      = "urn:ietf:params:oauth:grant-type:token-exchange"
	TokenTypeIDToken            = "urn:ietf:params:oauth:token-type:id_token"
	TokenTypeAccessToken        = "urn:ietf:params:oauth:token-type:access_token"
	TokenTypeJWT                = "urn:ietf:params:oauth:token-type:jwt"
)

// TokenExchangeConfig holds configuration for token exchange service
type TokenExchangeConfig struct {
	Enabled            bool     // Whether token exchange is enabled
	BrokerURL          string   // Token broker/exchange endpoint URL
	ClientID           string   // Client ID for token exchange
	ClientSecret       string   // Client secret for token exchange
	Audience           string   // Target audience for exchanged token (e.g., "vault")
	Resource           string   // Target resource URL (e.g., Vault API URL)
	RequestedScopes    []string // Requested scopes for exchanged token
	IntrospectionURL   string   // Token introspection endpoint
	ProviderCredentials map[string]string // Third-party provider credentials (e.g., Vault)
}

// TokenExchangeRequest represents RFC 8693 token exchange request
type TokenExchangeRequest struct {
	GrantType          string `json:"grant_type"`
	SubjectToken       string `json:"subject_token"`
	SubjectTokenType   string `json:"subject_token_type"`
	Audience           string `json:"audience,omitempty"`
	Resource           string `json:"resource,omitempty"`
	Scope              string `json:"scope,omitempty"`
	RequestedTokenType string `json:"requested_token_type,omitempty"`
}

// TokenExchangeResponse represents RFC 8693 token exchange response
type TokenExchangeResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int    `json:"expires_in,omitempty"`
	Scope           string `json:"scope,omitempty"`
	RefreshToken    string `json:"refresh_token,omitempty"`
}

// TokenIntrospectionRequest represents token introspection request (RFC 7662)
type TokenIntrospectionRequest struct {
	Token         string `json:"token"`
	TokenTypeHint string `json:"token_type_hint,omitempty"`
}

// TokenIntrospectionResponse represents token introspection response
type TokenIntrospectionResponse struct {
	Active    bool     `json:"active"`
	Scope     string   `json:"scope,omitempty"`
	ClientID  string   `json:"client_id,omitempty"`
	Username  string   `json:"username,omitempty"`
	TokenType string   `json:"token_type,omitempty"`
	Exp       int64    `json:"exp,omitempty"`
	Iat       int64    `json:"iat,omitempty"`
	Nbf       int64    `json:"nbf,omitempty"`
	Sub       string   `json:"sub,omitempty"`
	Aud       []string `json:"aud,omitempty"`
	Iss       string   `json:"iss,omitempty"`
}

// TokenExchangeService handles RFC 8693 token exchange operations
type TokenExchangeService struct {
	config     TokenExchangeConfig
	httpClient *http.Client
	logger     *log.Logger
}

// NewTokenExchangeService creates a new token exchange service
func NewTokenExchangeService(config TokenExchangeConfig, logger *log.Logger) *TokenExchangeService {
	return &TokenExchangeService{
		config: config,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		logger: logger,
	}
}

// ExchangeToken exchanges an ID token for a scoped access token (RFC 8693)
func (s *TokenExchangeService) ExchangeToken(ctx context.Context, idToken string) (*TokenExchangeResponse, error) {
	if !s.config.Enabled {
		return nil, fmt.Errorf("token exchange is not enabled")
	}

	s.logger.WithFields(log.Fields{
		"broker_url": s.config.BrokerURL,
		"audience":   s.config.Audience,
		"resource":   s.config.Resource,
	}).Debug("Initiating token exchange")

	// Step 1: Validate ID token through introspection
	introspection, err := s.IntrospectToken(ctx, idToken, "id_token")
	if err != nil {
		return nil, fmt.Errorf("token introspection failed: %w", err)
	}

	if !introspection.Active {
		return nil, fmt.Errorf("token is not active")
	}

	s.logger.WithFields(log.Fields{
		"subject":    introspection.Sub,
		"expires_at": time.Unix(introspection.Exp, 0),
		"scopes":     introspection.Scope,
	}).Debug("Token introspection successful")

	// Step 2: Perform token exchange
	scope := strings.Join(s.config.RequestedScopes, " ")
	
	exchangeReq := TokenExchangeRequest{
		GrantType:          GrantTypeTokenExchange,
		SubjectToken:       idToken,
		SubjectTokenType:   TokenTypeIDToken,
		Audience:           s.config.Audience,
		Resource:           s.config.Resource,
		Scope:              scope,
		RequestedTokenType: TokenTypeJWT,
	}

	formData := url.Values{}
	formData.Set("grant_type", exchangeReq.GrantType)
	formData.Set("subject_token", exchangeReq.SubjectToken)
	formData.Set("subject_token_type", exchangeReq.SubjectTokenType)
	if exchangeReq.Audience != "" {
		formData.Set("audience", exchangeReq.Audience)
	}
	if exchangeReq.Resource != "" {
		formData.Set("resource", exchangeReq.Resource)
	}
	if exchangeReq.Scope != "" {
		formData.Set("scope", exchangeReq.Scope)
	}
	if exchangeReq.RequestedTokenType != "" {
		formData.Set("requested_token_type", exchangeReq.RequestedTokenType)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", s.config.BrokerURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create exchange request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	
	// Add client authentication if configured
	if s.config.ClientID != "" && s.config.ClientSecret != "" {
		req.SetBasicAuth(s.config.ClientID, s.config.ClientSecret)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token exchange request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read exchange response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		s.logger.WithFields(log.Fields{
			"status_code": resp.StatusCode,
			"response":    string(body),
		}).Error("Token exchange failed")
		return nil, fmt.Errorf("token exchange failed with status %d: %s", resp.StatusCode, string(body))
	}

	var exchangeResp TokenExchangeResponse
	if err := json.Unmarshal(body, &exchangeResp); err != nil {
		return nil, fmt.Errorf("failed to parse exchange response: %w", err)
	}

	s.logger.WithFields(log.Fields{
		"token_type": exchangeResp.TokenType,
		"expires_in": exchangeResp.ExpiresIn,
		"scope":      exchangeResp.Scope,
	}).Info("Token exchange successful")

	return &exchangeResp, nil
}

// IntrospectToken introspects a token to validate it (RFC 7662)
func (s *TokenExchangeService) IntrospectToken(ctx context.Context, token string, tokenTypeHint string) (*TokenIntrospectionResponse, error) {
	if s.config.IntrospectionURL == "" {
		// If no introspection endpoint, perform basic JWT validation
		return s.basicTokenValidation(token)
	}

	formData := url.Values{}
	formData.Set("token", token)
	if tokenTypeHint != "" {
		formData.Set("token_type_hint", tokenTypeHint)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", s.config.IntrospectionURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create introspection request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	
	// Add client authentication
	if s.config.ClientID != "" && s.config.ClientSecret != "" {
		req.SetBasicAuth(s.config.ClientID, s.config.ClientSecret)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("introspection request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read introspection response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("introspection failed with status %d: %s", resp.StatusCode, string(body))
	}

	var introspectionResp TokenIntrospectionResponse
	if err := json.Unmarshal(body, &introspectionResp); err != nil {
		return nil, fmt.Errorf("failed to parse introspection response: %w", err)
	}

	return &introspectionResp, nil
}

// basicTokenValidation performs basic JWT validation without introspection
func (s *TokenExchangeService) basicTokenValidation(tokenString string) (*TokenIntrospectionResponse, error) {
	// Parse without validation first to extract claims
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}

	// Extract standard claims
	response := &TokenIntrospectionResponse{
		Active: true,
	}

	if sub, ok := claims["sub"].(string); ok {
		response.Sub = sub
	}

	if iss, ok := claims["iss"].(string); ok {
		response.Iss = iss
	}

	if exp, ok := claims["exp"].(float64); ok {
		response.Exp = int64(exp)
		// Check if token is expired
		if time.Now().Unix() > int64(exp) {
			response.Active = false
		}
	}

	if iat, ok := claims["iat"].(float64); ok {
		response.Iat = int64(iat)
	}

	if scope, ok := claims["scope"].(string); ok {
		response.Scope = scope
	}

	// Handle audience as string or array
	if aud, ok := claims["aud"].(string); ok {
		response.Aud = []string{aud}
	} else if audArray, ok := claims["aud"].([]interface{}); ok {
		for _, a := range audArray {
			if audStr, ok := a.(string); ok {
				response.Aud = append(response.Aud, audStr)
			}
		}
	}

	return response, nil
}

// ExchangeForVaultToken exchanges an ID token for a Vault JWT token
// This is a simplified exchange that directly uses the ID token for Vault auth
func (s *TokenExchangeService) ExchangeForVaultToken(ctx context.Context, idToken string) (string, error) {
	if !s.config.Enabled {
		// If exchange is not enabled, return the ID token directly for Vault auth
		s.logger.Warn("Token exchange disabled, using ID token directly for Vault authentication")
		return idToken, nil
	}

	// Perform token exchange
	exchangeResp, err := s.ExchangeToken(ctx, idToken)
	if err != nil {
		return "", fmt.Errorf("token exchange failed: %w", err)
	}

	// Return the exchanged access token (which should be a JWT suitable for Vault)
	return exchangeResp.AccessToken, nil
}

// LoadTokenExchangeConfigFromEnv loads token exchange configuration from environment variables
func LoadTokenExchangeConfigFromEnv() TokenExchangeConfig {
	enabled := os.Getenv("TOKEN_EXCHANGE_ENABLED") == "true"
	
	scopesStr := os.Getenv("TOKEN_EXCHANGE_SCOPES")
	var scopes []string
	if scopesStr != "" {
		scopes = strings.Split(scopesStr, ",")
		for i := range scopes {
			scopes[i] = strings.TrimSpace(scopes[i])
		}
	} else {
		// Default scopes for Vault
		scopes = []string{"vault:read", "vault:write"}
	}

	return TokenExchangeConfig{
		Enabled:          enabled,
		BrokerURL:        os.Getenv("TOKEN_EXCHANGE_BROKER_URL"),
		ClientID:         os.Getenv("TOKEN_EXCHANGE_CLIENT_ID"),
		ClientSecret:     os.Getenv("TOKEN_EXCHANGE_CLIENT_SECRET"),
		Audience:         getEnvOrDefault("TOKEN_EXCHANGE_AUDIENCE", "vault"),
		Resource:         os.Getenv("TOKEN_EXCHANGE_RESOURCE"),
		RequestedScopes:  scopes,
		IntrospectionURL: os.Getenv("TOKEN_EXCHANGE_INTROSPECTION_URL"),
	}
}
