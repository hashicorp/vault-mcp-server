// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package auth

import (
	"encoding/json"
	"fmt"
	"net/http"

	log "github.com/sirupsen/logrus"
)

// ProtectedResourceMetadata represents OAuth 2.0 Protected Resource Metadata
// as defined in RFC 9728
type ProtectedResourceMetadata struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers"`
	ScopesSupported        []string `json:"scopes_supported,omitempty"`
	BearerMethodsSupported []string `json:"bearer_methods_supported,omitempty"`
	ResourceSigningAlg     []string `json:"resource_signing_alg_values_supported,omitempty"`
	ResourceDocumentation  string   `json:"resource_documentation,omitempty"`
}

// MetadataHandler handles the Protected Resource Metadata endpoint
type MetadataHandler struct {
	config  Auth0Config
	baseURL string
	logger  *log.Logger
}

// NewMetadataHandler creates a new metadata handler
func NewMetadataHandler(config Auth0Config, baseURL string, logger *log.Logger) *MetadataHandler {
	return &MetadataHandler{
		config:  config,
		baseURL: baseURL,
		logger:  logger,
	}
}

// ServeHTTP handles requests to the Protected Resource Metadata endpoint
func (h *MetadataHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	metadata := h.buildMetadata()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(metadata); err != nil {
		h.logger.WithError(err).Error("Failed to encode metadata response")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	h.logger.Debug("Served Protected Resource Metadata")
}

// buildMetadata constructs the Protected Resource Metadata document
func (h *MetadataHandler) buildMetadata() ProtectedResourceMetadata {
	// Build the resource URL (the MCP server endpoint)
	resourceURL := h.baseURL

	// Authorization server is the OAuth provider domain
	authServer := h.config.Domain

	// Supported scopes from config
	scopes := h.config.RequiredScopes
	if len(scopes) == 0 {
		// Default MCP scopes
		scopes = []string{"mcp:tools", "mcp:resources", "mcp:prompts"}
	}

	return ProtectedResourceMetadata{
		Resource:               resourceURL,
		AuthorizationServers:   []string{authServer},
		ScopesSupported:        scopes,
		BearerMethodsSupported: []string{"header"},
		ResourceSigningAlg:     []string{"RS256"},
		ResourceDocumentation:  h.baseURL + "/docs",
	}
}

// AuthServerMetadataHandler returns OAuth provider discovery information
// This is a helper that redirects to the provider's well-known endpoints
type AuthServerMetadataHandler struct {
	config Auth0Config
	logger *log.Logger
}

// NewAuthServerMetadataHandler creates a new auth server metadata handler
func NewAuthServerMetadataHandler(config Auth0Config, logger *log.Logger) *AuthServerMetadataHandler {
	return &AuthServerMetadataHandler{
		config: config,
		logger: logger,
	}
}

// ServeHTTP redirects to the OAuth provider's discovery endpoint
func (h *AuthServerMetadataHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var redirectURL string

	// Build discovery URL based on provider
	if h.config.Provider == ProviderOkta {
		// Okta uses /oauth2/{authServerID}/.well-known/openid-configuration
		authServerID := h.config.AuthServerID
		if authServerID == "" {
			authServerID = "default"
		}
		redirectURL = fmt.Sprintf("%s/oauth2/%s/.well-known/openid-configuration", h.config.Domain, authServerID)
	} else {
		// Auth0 and others use /.well-known/openid-configuration
		redirectURL = h.config.Domain + "/.well-known/openid-configuration"
	}

	h.logger.Debugf("Redirecting to OAuth provider discovery: %s", redirectURL)
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// WWWAuthenticateHeader constructs the WWW-Authenticate header value
// as defined in RFC 6750 and RFC 9728
func WWWAuthenticateHeader(realm string, resourceMetadataURL string, scopes []string) string {
	header := fmt.Sprintf(`Bearer realm="%s"`, realm)

	if resourceMetadataURL != "" {
		header += fmt.Sprintf(`, resource_metadata="%s"`, resourceMetadataURL)
	}

	if len(scopes) > 0 {
		scopeStr := ""
		for i, scope := range scopes {
			if i > 0 {
				scopeStr += " "
			}
			scopeStr += scope
		}
		header += fmt.Sprintf(`, scope="%s"`, scopeStr)
	}

	return header
}
