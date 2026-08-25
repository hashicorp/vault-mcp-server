// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package auth

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const (
	// tokenTypeAccessToken is the RFC 8693 token type URI for an access token.
	tokenTypeAccessToken = "urn:ietf:params:oauth:token-type:access_token"

	// grantTypeTokenExchange is the RFC 8693 grant type URI.
	grantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
)

// ExchangeTokens performs an RFC 8693 token exchange against the STS at stsEndpoint,
// combining the Subject and Actor access tokens into a Delegation JWT.
//
// It POSTs a token-exchange request to stsEndpoint, reads the access_token from the
// JSON response (which is the raw Delegation JWT string), and returns the result of
// ParseUnsigned — giving the caller a ready-to-use *DelegationJWT.
//
// Errors:
//   - A descriptive error (including HTTP status) when the STS returns a non-2xx response.
//   - ErrTokenExpired when the returned JWT has an already-expired exp claim.
//   - Any parse error surfaced by ParseUnsigned for a malformed JWT.
// clientID and clientSecret are the IBM Verify credentials for the STS endpoint.
// When clientSecret is non-empty, HTTP Basic auth (client_secret_basic) is used.
// When clientSecret is empty, clientID is sent in the POST body (public client).
func ExchangeTokens(subjectToken, actorToken, stsEndpoint, clientID, clientSecret string) (*DelegationJWT, error) {
	body := url.Values{}
	body.Set("grant_type", grantTypeTokenExchange)
	body.Set("subject_token", subjectToken)
	body.Set("subject_token_type", tokenTypeAccessToken)
	body.Set("actor_token", actorToken)
	body.Set("actor_token_type", tokenTypeAccessToken)

	var useBasicAuth bool
	if clientSecret != "" {
		useBasicAuth = true
	} else {
		body.Set("client_id", clientID)
	}

	req, err := http.NewRequest(http.MethodPost, stsEndpoint, strings.NewReader(body.Encode()))
	if err != nil {
		return nil, fmt.Errorf("auth: building STS request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if useBasicAuth {
		req.SetBasicAuth(clientID, clientSecret)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("auth: STS token exchange POST failed: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("auth: reading STS response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("auth: STS returned HTTP %d: %s", resp.StatusCode, string(raw))
	}

	// tokenResponse is defined in pkce.go (same package).
	var tok tokenResponse
	if err := json.Unmarshal(raw, &tok); err != nil {
		return nil, fmt.Errorf("auth: parsing STS response: %w", err)
	}
	if tok.Error != "" {
		return nil, fmt.Errorf("auth: STS error %q: %s", tok.Error, tok.ErrorDesc)
	}
	if tok.AccessToken == "" {
		return nil, fmt.Errorf("auth: STS response missing access_token")
	}

	return ParseUnsigned(tok.AccessToken)
}
