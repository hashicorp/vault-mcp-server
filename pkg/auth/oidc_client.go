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
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

// OIDCDiscovery represents OIDC discovery document
type OIDCDiscovery struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	JwksURI               string   `json:"jwks_uri"`
	ScopesSupported       []string `json:"scopes_supported"`
}

// TokenResponse represents an OAuth 2.0 token response
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// OIDCClient handles OIDC authentication flows
type OIDCClient struct {
	config     OIDCConfig
	discovery  *OIDCDiscovery
	httpClient *http.Client
	logger     *log.Logger
}

// NewOIDCClient creates a new OIDC client
func NewOIDCClient(config OIDCConfig, logger *log.Logger) (*OIDCClient, error) {
	client := &OIDCClient{
		config: config,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		logger: logger,
	}

	// Perform OIDC discovery
	discovery, err := client.discover()
	if err != nil {
		return nil, fmt.Errorf("OIDC discovery failed: %w", err)
	}
	client.discovery = discovery

	logger.WithFields(log.Fields{
		"issuer":        discovery.Issuer,
		"auth_endpoint": discovery.AuthorizationEndpoint,
	}).Info("OIDC discovery completed")

	return client, nil
}

// discover performs OIDC discovery to find endpoints
func (c *OIDCClient) discover() (*OIDCDiscovery, error) {
	discoveryURL := strings.TrimSuffix(c.config.Issuer, "/") + "/.well-known/openid-configuration"

	c.logger.WithField("url", discoveryURL).Debug("Fetching OIDC discovery document")

	resp, err := c.httpClient.Get(discoveryURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch discovery document: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("discovery request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var discovery OIDCDiscovery
	if err := json.NewDecoder(resp.Body).Decode(&discovery); err != nil {
		return nil, fmt.Errorf("failed to decode discovery document: %w", err)
	}

	return &discovery, nil
}

// BuildAuthorizeURL constructs the OIDC authorization URL with PKCE
func (c *OIDCClient) BuildAuthorizeURL(codeChallenge, state string) string {
	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", c.config.ClientID)
	params.Set("redirect_uri", c.config.RedirectURI)
	params.Set("scope", strings.Join(c.config.Scopes, " "))
	params.Set("state", state)
	params.Set("code_challenge", codeChallenge)
	params.Set("code_challenge_method", "S256")

	// Add audience if configured (required for Okta to include aud claim)
	if c.config.Audience != "" {
		params.Set("audience", c.config.Audience)
	}

	// Add prompt=consent to ensure refresh token is issued
	if c.config.RequestRefreshToken {
		params.Set("prompt", "consent")
	}

	authorizeURL := c.discovery.AuthorizationEndpoint + "?" + params.Encode()

	c.logger.WithFields(log.Fields{
		"client_id": c.config.ClientID,
		"scopes":    strings.Join(c.config.Scopes, " "),
		"state":     state[:8] + "...", // Log only first 8 chars for security
	}).Debug("Built authorization URL")

	return authorizeURL
}

// ExchangeCodeForTokens exchanges an authorization code for tokens using PKCE
func (c *OIDCClient) ExchangeCodeForTokens(code, codeVerifier string) (*TokenResponse, error) {
	c.logger.Debug("Exchanging authorization code for tokens")

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", c.config.RedirectURI)
	data.Set("client_id", c.config.ClientID)
	data.Set("code_verifier", codeVerifier)

	// Add client secret if configured (for confidential clients)
	if c.config.ClientSecret != "" {
		data.Set("client_secret", c.config.ClientSecret)
	}

	req, err := http.NewRequest(http.MethodPost, c.discovery.TokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	c.logger.WithFields(log.Fields{
		"token_type":   tokenResp.TokenType,
		"expires_in":   tokenResp.ExpiresIn,
		"has_refresh":  tokenResp.RefreshToken != "",
		"has_id_token": tokenResp.IDToken != "",
	}).Info("Successfully exchanged code for tokens")

	return &tokenResp, nil
}

// RefreshTokens refreshes the access token using a refresh token
func (c *OIDCClient) RefreshTokens(refreshToken string) (*TokenResponse, error) {
	c.logger.Debug("Refreshing access token")

	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)
	data.Set("client_id", c.config.ClientID)

	// Add client secret if configured
	if c.config.ClientSecret != "" {
		data.Set("client_secret", c.config.ClientSecret)
	}

	req, err := http.NewRequest(http.MethodPost, c.discovery.TokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create refresh request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to refresh token: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token refresh failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode refresh response: %w", err)
	}

	c.logger.WithFields(log.Fields{
		"token_type": tokenResp.TokenType,
		"expires_in": tokenResp.ExpiresIn,
	}).Info("Successfully refreshed access token")

	return &tokenResp, nil
}

// InitiateAuthFlow initiates the complete OIDC authentication flow with PKCE
func (c *OIDCClient) InitiateAuthFlow(callbackPort int) (*TokenCache, error) {
	c.logger.Info("Initiating OIDC authentication flow")

	// Generate PKCE challenge
	pkce, err := GeneratePKCEChallenge()
	if err != nil {
		return nil, fmt.Errorf("failed to generate PKCE challenge: %w", err)
	}

	// Generate state for CSRF protection
	state, err := GenerateState()
	if err != nil {
		return nil, fmt.Errorf("failed to generate state: %w", err)
	}

	// Save PKCE state to disk
	pkceState := &PKCEState{
		CodeVerifier: pkce.CodeVerifier,
		State:        state,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(10 * time.Minute),
	}
	if err := SavePKCEState(pkceState, c.logger); err != nil {
		return nil, fmt.Errorf("failed to save PKCE state: %w", err)
	}

	// Start callback server
	callbackServer, err := NewCallbackServer(callbackPort, c.logger)
	if err != nil {
		return nil, fmt.Errorf("failed to start callback server: %w", err)
	}
	callbackServer.Start()

	// Ensure callback server is shut down
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := callbackServer.Shutdown(ctx); err != nil {
			c.logger.WithError(err).Warn("Failed to shutdown callback server")
		}
	}()

	// Build authorization URL
	authorizeURL := c.BuildAuthorizeURL(pkce.CodeChallenge, state)

	// Open browser (with fallback to print URL)
	OpenBrowserWithFallback(authorizeURL, c.logger)

	// Wait for callback
	c.logger.WithField("timeout", c.config.AuthTimeout).Info("Waiting for authentication callback...")
	result, err := callbackServer.WaitForCallback(c.config.AuthTimeout)
	if err != nil {
		return nil, err
	}

	// Validate state
	if result.State != state {
		return nil, fmt.Errorf("state mismatch: CSRF attack detected")
	}

	c.logger.Debug("State validated successfully")

	// Exchange code for tokens
	tokenResp, err := c.ExchangeCodeForTokens(result.Code, pkce.CodeVerifier)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code for tokens: %w", err)
	}

	// Clear PKCE state
	if err := ClearPKCEState(c.logger); err != nil {
		c.logger.WithError(err).Warn("Failed to clear PKCE state")
	}

	// Calculate token expiry
	expiresAt := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)

	// Extract user ID from ID token (if present)
	userID := ""
	if tokenResp.IDToken != "" {
		claims, err := ExtractClaims(tokenResp.IDToken)
		if err == nil {
			if sub, ok := claims["sub"].(string); ok {
				userID = sub
			}
		}
	}

	// Create token cache
	cache := &TokenCache{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		IDToken:      tokenResp.IDToken,
		TokenType:    tokenResp.TokenType,
		ExpiresAt:    expiresAt,
		UserID:       userID,
		CachedAt:     time.Now(),
	}

	// Save token cache
	if err := SaveCache(cache, c.logger); err != nil {
		c.logger.WithError(err).Warn("Failed to save token cache")
	}

	c.logger.WithFields(log.Fields{
		"user_id":    userID,
		"expires_at": expiresAt.Format(time.RFC3339),
	}).Info("OIDC authentication completed successfully")

	return cache, nil
}

// ExtractClaims extracts claims from a JWT token without validation
// This is a simple extraction for getting the sub claim, not for security validation
func ExtractClaims(token string) (map[string]interface{}, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format")
	}

	// Decode payload (second part)
	payload, err := base64URLDecode(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %w", err)
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal claims: %w", err)
	}

	return claims, nil
}

// base64URLDecode decodes a base64-URL encoded string
func base64URLDecode(s string) ([]byte, error) {
	// Add padding if necessary
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	// Replace URL-safe characters
	s = strings.Replace(s, "-", "+", -1)
	s = strings.Replace(s, "_", "/", -1)
	// Decode
	return json.RawMessage(s).MarshalJSON()
}
