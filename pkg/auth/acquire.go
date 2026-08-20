// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package auth

import (
	"context"
	"fmt"
	"time"
)

// AuthConfig holds the configuration for the OBO delegation pipeline.
// When Enabled is false, AcquireTokens is a no-op and the server falls back
// to the VAULT_TOKEN environment variable path.
type AuthConfig struct {
	// Enabled activates the OBO pipeline when true.
	// Corresponds to VAULT_MCP_AUTH_ENABLED=true.
	Enabled bool

	// ClientID is the OAuth client identifier (used in both PKCE flows and STS).
	ClientID string
	// AuthURL is the IdP authorization endpoint.
	AuthURL string
	// TokenURL is the IdP token endpoint for PKCE code exchange.
	TokenURL string
	// RedirectURL is the local callback URL (e.g. http://localhost:49152/callback).
	RedirectURL string
	// Scopes is the list of OAuth scopes to request.
	Scopes []string

	// STSEndpoint is the RFC 8693 token exchange endpoint.
	STSEndpoint string

	// Deadline is the per-PKCE-flow timeout. Defaults to 5 minutes when zero.
	Deadline time.Duration
}

// PKCERunner is a function with the same signature as RunPKCEFlows.
// It is exposed so that callers (tests) can substitute a fake implementation
// without opening a browser or binding a network port.
type PKCERunner func(ctx context.Context, cfg PKCEConfig) (*PKCEResult, error)

// AcquireTokens runs the full OBO delegation pipeline:
//  1. Two sequential PKCE Authorization Code flows via pkceRunner (Subject + Actor).
//  2. RFC 8693 token exchange against cfg.STSEndpoint.
//  3. Lightweight JWT parse of the resulting Delegation JWT.
//
// Returns (nil, nil) when cfg.Enabled is false — the caller should fall back to
// the VAULT_TOKEN environment variable path.
//
// pkceRunner is normally RunPKCEFlows; tests substitute a fake to avoid browser/port
// interactions.
func AcquireTokens(ctx context.Context, cfg AuthConfig, pkceRunner PKCERunner) (*DelegationJWT, error) {
	if !cfg.Enabled {
		return nil, nil
	}

	pkceResult, err := pkceRunner(ctx, PKCEConfig{
		ClientID:    cfg.ClientID,
		AuthURL:     cfg.AuthURL,
		TokenURL:    cfg.TokenURL,
		RedirectURL: cfg.RedirectURL,
		Scopes:      cfg.Scopes,
		Deadline:    cfg.Deadline,
	})
	if err != nil {
		return nil, fmt.Errorf("auth: PKCE flows failed: %w", err)
	}

	jwt, err := ExchangeTokens(pkceResult.SubjectToken, pkceResult.ActorToken, cfg.STSEndpoint)
	if err != nil {
		return nil, fmt.Errorf("auth: STS token exchange failed: %w", err)
	}

	return jwt, nil
}
