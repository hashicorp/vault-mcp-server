// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package oauth

// TokenType identifies the kind of payload sealed in a token. Parsing always
// asserts the expected type so a token minted for one purpose cannot be replayed
// as another.
type TokenType string

const (
	TokenTypeClientID    TokenType = "client_id"
	TokenTypeAuthState   TokenType = "auth_state"
	TokenTypeAuthCode    TokenType = "auth_code"
	TokenTypeAccessToken TokenType = "access_token"
	TokenTypeOIDCState   TokenType = "oidc_state"
)

// ClientRegistrationData is sealed into the OAuth client_id. It exists only to
// validate redirect URIs and echo back registration metadata.
type ClientRegistrationData struct {
	ClientIDIssuedAt int64    `json:"client_id_issued_at"`
	RedirectURIs     []string `json:"redirect_uris"`

	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`

	ClientName string `json:"client_name,omitempty"`
	Scope      string `json:"scope,omitempty"`
}

// AuthState is sealed into a short-lived blob passed to the login page. It
// preserves the OAuth request across the interactive Vault login.
type AuthState struct {
	RedirectURI          string   `json:"redirect_uri"`
	CodeChallenge        string   `json:"code_challenge"`
	CodeChallengeMethod  string   `json:"code_challenge_method"`
	State                string   `json:"state,omitempty"`
	Scopes               []string `json:"scopes,omitempty"`
	ClientID             string   `json:"client_id"`
	CreatedAtUnixSeconds int64    `json:"created_at"`
}

// AuthCodeData is sealed into the OAuth authorization code. It carries the Vault
// token obtained during login so /token can exchange it for an access token
// without any server-side storage.
type AuthCodeData struct {
	VaultToken           string   `json:"vault_token"`
	VaultAddr            string   `json:"vault_addr,omitempty"`
	VaultNamespace       string   `json:"vault_namespace,omitempty"`
	RedirectURI          string   `json:"redirect_uri"`
	CodeChallenge        string   `json:"code_challenge"`
	CodeChallengeMethod  string   `json:"code_challenge_method"`
	State                string   `json:"state,omitempty"`
	Scopes               []string `json:"scopes,omitempty"`
	ClientID             string   `json:"client_id"`
	CreatedAtUnixSeconds int64    `json:"created_at"`
}

// AccessTokenData is sealed into the OAuth bearer access token. The bearer
// middleware unseals it and injects these values into the request context.
type AccessTokenData struct {
	VaultToken           string `json:"vault_token"`
	VaultAddr            string `json:"vault_addr,omitempty"`
	VaultNamespace       string `json:"vault_namespace,omitempty"`
	Subject              string `json:"sub,omitempty"`
	CreatedAtUnixSeconds int64  `json:"created_at"`
}

// OIDCRoundTrip is sealed into the cookie set while the browser is at the
// identity provider, so the callback can resume the original OAuth request
// without server-side state.
type OIDCRoundTrip struct {
	AuthState   string `json:"auth_state"`
	ClientNonce string `json:"client_nonce"`
	RedirectURI string `json:"redirect_uri"`
}
