// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package auth

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
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
// authorizationDetails is an optional RFC 9396 RAR JSON array (e.g.
// `[{"type":"vault:path_access","path":"secret/data/foo","capabilities":["read"]}]`).
// When non-empty it is forwarded as the authorization_details POST parameter so the
// STS scopes the issued delegation token to the requested paths and capabilities.
//
// Errors:
//   - A descriptive error (including HTTP status) when the STS returns a non-2xx response.
//   - ErrTokenExpired when the returned JWT has an already-expired exp claim.
//   - Any parse error surfaced by ParseUnsigned for a malformed JWT.
//
// clientID and clientSecret are the IBM Verify credentials for the STS endpoint.
// When clientSecret is non-empty, HTTP Basic auth (client_secret_basic) is used.
// When clientSecret is empty, clientID is sent in the POST body (public client).
// VAULT_MCP_STS_PRIVATE_KEY_FILE opts into RS256 private_key_jwt instead of Basic
// auth. VAULT_MCP_STS_KEY_ID and VAULT_MCP_STS_ASSERTION_AUDIENCE are optional.
func ExchangeTokens(subjectToken, actorToken, stsEndpoint, clientID, clientSecret, authorizationDetails string) (*DelegationJWT, error) {
	body := url.Values{}
	body.Set("grant_type", grantTypeTokenExchange)
	body.Set("subject_token", subjectToken)
	body.Set("subject_token_type", tokenTypeAccessToken)
	body.Set("actor_token", actorToken)
	body.Set("actor_token_type", tokenTypeAccessToken)
	if authorizationDetails != "" {
		body.Set("authorization_details", authorizationDetails)
	}

	var useBasicAuth bool
	if keyFile := os.Getenv("VAULT_MCP_STS_PRIVATE_KEY_FILE"); keyFile != "" {
		assertion, err := stsClientAssertion(keyFile, clientID, stsEndpoint)
		if err != nil {
			return nil, fmt.Errorf("auth: signing STS client assertion: %w", err)
		}
		body.Set("client_id", clientID)
		body.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		body.Set("client_assertion", assertion)
	} else if clientSecret != "" {
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

func stsClientAssertion(keyFile, clientID, stsEndpoint string) (string, error) {
	if clientID == "" {
		return "", fmt.Errorf("STS client ID is required for private_key_jwt")
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return "", fmt.Errorf("reading private key: %w", err)
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return "", fmt.Errorf("private key must be unencrypted RSA PEM (PKCS#1 or PKCS#8)")
	}
	var key *rsa.PrivateKey
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		var parsed any
		parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		if err == nil {
			var ok bool
			key, ok = parsed.(*rsa.PrivateKey)
			if !ok {
				return "", fmt.Errorf("private_key_jwt requires an RSA private key for RS256")
			}
		}
	default:
		return "", fmt.Errorf("private key must be unencrypted RSA PEM (PKCS#1 or PKCS#8)")
	}
	if err != nil {
		return "", fmt.Errorf("parsing RSA private key: %w", err)
	}
	if err := key.Validate(); err != nil {
		return "", fmt.Errorf("invalid RSA private key: %w", err)
	}
	if key.N.BitLen() < 2048 {
		return "", fmt.Errorf("RSA private key must be at least 2048 bits")
	}
	header := map[string]string{"alg": "RS256", "typ": "JWT"}
	if kid := os.Getenv("VAULT_MCP_STS_KEY_ID"); kid != "" {
		header["kid"] = kid
	}
	audience := os.Getenv("VAULT_MCP_STS_ASSERTION_AUDIENCE")
	if audience == "" {
		audience = stsEndpoint
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", fmt.Errorf("generating assertion ID: %w", err)
	}
	now := time.Now().Unix()
	// These fixed shapes contain only JSON-supported string and integer values.
	headerJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(struct {
		Iss string `json:"iss"`
		Sub string `json:"sub"`
		Aud string `json:"aud"`
		Iat int64  `json:"iat"`
		Exp int64  `json:"exp"`
		Jti string `json:"jti"`
	}{clientID, clientID, audience, now, now + 60, base64.RawURLEncoding.EncodeToString(nonce[:])})
	input := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	digest := sha256.Sum256([]byte(input))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("signing assertion: %w", err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}
