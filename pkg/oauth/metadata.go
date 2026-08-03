// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package oauth

import (
	"encoding/json"
	"net/http"
)

type authServerMetadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	RegistrationEndpoint              string   `json:"registration_endpoint"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
}

type protectedResourceMetadata struct {
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers"`
}

// serverCard advertises the MCP server and its OAuth capability.
func (r *Router) serverCard(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	base := r.cfg.BaseURL(req)
	writeJSON(w, map[string]any{
		"name":        "com.viasat.vault-mcp",
		"title":       "Vault MCP Server",
		"description": "Manage HashiCorp Vault secrets, mounts, and PKI via MCP tools.",
		"homepage":    base,
		"transports": []map[string]any{
			{"type": "streamable-http", "url": base + "/mcp"},
		},
		"auth": map[string]any{
			"type":                   "oauth2",
			"authorizationServerUrl": base,
		},
		"tags": []string{"vault", "secrets", "pki", "security"},
	})
}

// authorizationServerMetadata implements RFC 8414 discovery.
func (r *Router) authorizationServerMetadata(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	base := r.cfg.BaseURL(req)
	w.Header().Set("Access-Control-Allow-Origin", "*")
	writeJSON(w, authServerMetadata{
		Issuer:                            base,
		AuthorizationEndpoint:             base + "/authorize",
		TokenEndpoint:                     base + "/token",
		RegistrationEndpoint:              base + "/register",
		ResponseTypesSupported:            []string{"code"},
		GrantTypesSupported:               []string{"authorization_code"},
		CodeChallengeMethodsSupported:     []string{"S256"},
		TokenEndpointAuthMethodsSupported: []string{"none"},
	})
}

// protectedResourceMetadata implements RFC 9728 so MCP clients can discover the
// authorization server protecting the /mcp resource.
func (r *Router) protectedResourceMetadata(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	base := r.cfg.BaseURL(req)
	w.Header().Set("Access-Control-Allow-Origin", "*")
	writeJSON(w, protectedResourceMetadata{
		Resource:             base + "/mcp",
		AuthorizationServers: []string{base},
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
