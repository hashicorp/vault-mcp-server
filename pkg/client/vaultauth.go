// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/api"
)

// VaultAuthParams configures how the login helpers reach the upstream Vault.
type VaultAuthParams struct {
	Address       string
	Namespace     string
	SkipTLSVerify bool
}

// loginClient builds a short-lived, unregistered Vault client for an auth call.
func loginClient(p VaultAuthParams) (*api.Client, error) {
	return newConfiguredVaultClient(p.Address, p.SkipTLSVerify, "", p.Namespace)
}

// LoginUserpass authenticates against the userpass auth method and returns the
// resulting Vault client token.
func LoginUserpass(ctx context.Context, p VaultAuthParams, mount, username, password string) (string, error) {
	return loginWithPassword(ctx, p, mount, username, password)
}

// LoginLDAP authenticates against the ldap auth method and returns the resulting
// Vault client token.
func LoginLDAP(ctx context.Context, p VaultAuthParams, mount, username, password string) (string, error) {
	return loginWithPassword(ctx, p, mount, username, password)
}

// loginWithPassword performs POST auth/{mount}/login/{username} with a password,
// which is the shape shared by the userpass and ldap auth methods.
func loginWithPassword(ctx context.Context, p VaultAuthParams, mount, username, password string) (string, error) {
	vc, err := loginClient(p)
	if err != nil {
		return "", err
	}

	path := fmt.Sprintf("auth/%s/login/%s", mount, username)
	secret, err := vc.Logical().WriteWithContext(ctx, path, map[string]interface{}{
		"password": password,
	})
	if err != nil {
		return "", fmt.Errorf("vault login failed: %w", err)
	}
	if secret == nil || secret.Auth == nil || secret.Auth.ClientToken == "" {
		return "", fmt.Errorf("vault login returned no client token")
	}
	return secret.Auth.ClientToken, nil
}

// LookupToken validates a Vault token by calling auth/token/lookup-self with it.
// It returns nil when the token is valid.
func LookupToken(ctx context.Context, p VaultAuthParams, token string) error {
	c, err := newConfiguredVaultClient(p.Address, p.SkipTLSVerify, token, p.Namespace)
	if err != nil {
		return err
	}
	if _, err := c.Auth().Token().LookupSelfWithContext(ctx); err != nil {
		return fmt.Errorf("vault token lookup failed: %w", err)
	}
	return nil
}

// OIDCAuthURL initiates the OIDC login flow and returns the identity provider
// authorization URL the browser should be redirected to. redirectURI must be a
// callback on this server that the Vault OIDC role permits in allowed_redirect_uris.
func OIDCAuthURL(ctx context.Context, p VaultAuthParams, mount, role, redirectURI, clientNonce string) (string, error) {
	vc, err := loginClient(p)
	if err != nil {
		return "", err
	}

	data := map[string]interface{}{
		"redirect_uri": redirectURI,
		"client_nonce": clientNonce,
	}
	if role != "" {
		data["role"] = role
	}

	path := fmt.Sprintf("auth/%s/oidc/auth_url", mount)
	secret, err := vc.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		return "", fmt.Errorf("vault oidc auth_url failed: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return "", fmt.Errorf("vault oidc auth_url returned no data")
	}
	authURL, _ := secret.Data["auth_url"].(string)
	if authURL == "" {
		return "", fmt.Errorf("vault oidc auth_url returned empty url (check role/redirect_uri)")
	}
	return authURL, nil
}

// OIDCCallback completes the OIDC login flow by exchanging the IdP state/code for
// a Vault client token via GET auth/{mount}/oidc/callback.
func OIDCCallback(ctx context.Context, p VaultAuthParams, mount, state, code, clientNonce string) (string, error) {
	vc, err := loginClient(p)
	if err != nil {
		return "", err
	}

	path := fmt.Sprintf("auth/%s/oidc/callback", mount)
	secret, err := vc.Logical().ReadWithDataWithContext(ctx, path, map[string][]string{
		"state":        {state},
		"code":         {code},
		"client_nonce": {clientNonce},
	})
	if err != nil {
		return "", fmt.Errorf("vault oidc callback failed: %w", err)
	}
	if secret == nil || secret.Auth == nil || secret.Auth.ClientToken == "" {
		return "", fmt.Errorf("vault oidc callback returned no client token")
	}
	return secret.Auth.ClientToken, nil
}
