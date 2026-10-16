// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package auth

import (
	"net/url"
	"strings"
)

// PasswordGrant authenticates the agent (actor) non-interactively with the
// OAuth resource-owner password credentials grant (RFC 6749 §4.3), so no
// browser sign-in is needed. Client authentication is the same as the PKCE
// code exchange (client_secret_basic when cfg.ClientSecret is set).
// The Verify application must have the password grant enabled.
func PasswordGrant(cfg PKCEConfig, username, password string) PKCEFlowResult {
	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("username", username)
	form.Set("password", password)
	if len(cfg.Scopes) > 0 {
		form.Set("scope", strings.Join(cfg.Scopes, " "))
	}
	tok, err := postTokenForm(cfg.TokenURL, cfg.ClientID, cfg.ClientSecret, form)
	return PKCEFlowResult{Token: tok, Err: err}
}
