// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

// Package oauth implements a stateless OAuth 2.1 Authorization Server that lets
// MCP clients drive a browser login against an upstream HashiCorp Vault. The
// Vault token obtained during login is sealed (AES-256-GCM) into the OAuth
// bearer token; the bearer middleware unseals it on each MCP request and injects
// it into the request context. No session state is stored server-side.
package oauth

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/vault-mcp-server/pkg/client"
	log "github.com/sirupsen/logrus"
)

// Router wires the OAuth endpoints and bearer middleware.
type Router struct {
	cfg      Config
	logger   *log.Logger
	tokenSvc *Service
}

// NewRouter constructs a Router from cfg. It returns an error if the auth secret
// is not a valid sealer key.
func NewRouter(cfg Config, logger *log.Logger) (*Router, error) {
	sealer, err := NewSealer(cfg.MCPAuthSecret)
	if err != nil {
		return nil, err
	}
	return &Router{
		cfg:      cfg,
		logger:   logger,
		tokenSvc: NewService(sealer, time.Now),
	}, nil
}

// Register mounts all OAuth + discovery endpoints on mux.
func (r *Router) Register(mux *http.ServeMux) {
	// Discovery.
	mux.HandleFunc("/.well-known/mcp/server-card.json", r.serverCard)
	mux.HandleFunc("/.well-known/oauth-authorization-server", r.authorizationServerMetadata)
	mux.HandleFunc("/.well-known/oauth-protected-resource", r.protectedResourceMetadata)
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", r.protectedResourceMetadata)

	// OAuth endpoints.
	mux.HandleFunc("/register", r.registerClient)
	mux.HandleFunc("/authorize", r.authorize)
	mux.HandleFunc("/token", r.token)

	// Interactive Vault login + OIDC passthrough.
	mux.HandleFunc("/vault/login", r.vaultLogin)
	mux.HandleFunc("/vault/oidc/start", r.oidcStart)
	// /oidc/callback is the path Vault has pre-registered for localhost:8250,
	// so it must live on the main mux. /vault/oidc/callback is kept as an alias.
	mux.HandleFunc("/oidc/callback", r.oidcCallback)
	mux.HandleFunc("/vault/oidc/callback", r.oidcCallback)
}

// BearerMiddleware protects the wrapped MCP handler. A valid sealed bearer token
// is unsealed and its Vault credentials injected into the request context.
//
// If a Vault token is supplied externally (via VAULT_TOKEN env var or X-Vault-Token
// header), the request is permitted when the bearer is missing or invalid.
//
// Otherwise, when the bearer is missing or invalid it returns 401 with a
// WWW-Authenticate challenge so MCP clients begin the OAuth flow.
func (r *Router) BearerMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		authz := req.Header.Get("Authorization")
		if strings.HasPrefix(strings.ToLower(authz), "bearer ") {
			token := strings.TrimSpace(authz[len("bearer "):])
			var at AccessTokenData
			if _, err := r.tokenSvc.Parse(string(TokenTypeAccessToken), token, &at); err == nil {
				ctx := client.ContextWithVaultAuth(req.Context(), at.VaultAddr, at.VaultToken, at.VaultNamespace)
				next.ServeHTTP(w, req.WithContext(ctx))
				return
			}
			// Fall through to external token bypass.
		}

		// External token bypass (for clients that cannot do OAuth).
		if strings.TrimSpace(req.Header.Get(client.VaultHeaderToken)) != "" ||
			strings.TrimSpace(req.Header.Get(client.VaultToken)) != "" ||
			strings.TrimSpace(os.Getenv(client.VaultToken)) != "" {
			next.ServeHTTP(w, req)
			return
		}

		r.challenge(w, req)
	})
}

// challenge responds with a 401 and a WWW-Authenticate header pointing MCP
// clients at the protected-resource metadata to begin the OAuth flow.
func (r *Router) challenge(w http.ResponseWriter, req *http.Request) {
	resourceMeta := r.cfg.BaseURL(req) + "/.well-known/oauth-protected-resource/mcp"
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata=%q`, resourceMeta))
	http.Error(w, "authentication required", http.StatusUnauthorized)
}

// vaultAuthParams builds the upstream Vault connection parameters from config.
func (r *Router) vaultAuthParams() client.VaultAuthParams {
	addr := r.cfg.VaultAddr
	if addr == "" {
		addr = client.DefaultVaultAddress
	}
	return client.VaultAuthParams{
		Address:       addr,
		Namespace:     r.cfg.VaultNamespace,
		SkipTLSVerify: skipTLSVerifyEnv(),
	}
}

func skipTLSVerifyEnv() bool {
	if v := strings.TrimSpace(os.Getenv(client.VaultSkipTLSVerify)); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return false
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

func splitScopes(scope string) []string {
	fields := strings.Fields(strings.TrimSpace(scope))
	if len(fields) == 0 {
		return nil
	}
	out := make([]string, 0, len(fields))
	seen := make(map[string]struct{}, len(fields))
	for _, f := range fields {
		if _, ok := seen[f]; ok {
			continue
		}
		seen[f] = struct{}{}
		out = append(out, f)
	}
	return out
}
