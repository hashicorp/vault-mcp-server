// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package auth

import (
	"errors"
	"net/url"
	"strings"
)

// ErrActorCredentialsMissing is returned when the actor OAuth client is not fully configured.
var ErrActorCredentialsMissing = errors.New("actor OAuth client credentials not configured (set VAULT_MCP_ACTOR_CLIENT_ID and VAULT_MCP_ACTOR_CLIENT_SECRET)")

// ClientCredentialsGrant authenticates the agent (actor) as an OAuth client
// with the client credentials grant (RFC 6749 §4.4), so no browser sign-in is
// needed. The client authenticates with client_secret_post (credentials in the
// request body), and the application must be a confidential client with this
// grant enabled and its token endpoint auth method set to client_secret_post.
func ClientCredentialsGrant(cfg PKCEConfig) PKCEFlowResult {
	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		return PKCEFlowResult{Err: ErrActorCredentialsMissing}
	}
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", cfg.ClientID)
	form.Set("client_secret", cfg.ClientSecret)
	if len(cfg.Scopes) > 0 {
		form.Set("scope", strings.Join(cfg.Scopes, " "))
	}
	// An empty secret makes postTokenForm skip Basic auth; the credentials are
	// already in the body.
	tok, err := postTokenForm(cfg.TokenURL, cfg.ClientID, "", form)
	return PKCEFlowResult{Token: tok, Err: err}
}
