// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/vault/api"
	log "github.com/sirupsen/logrus"
)

const (
	VaultAuthMethod      = "VAULT_AUTH_METHOD"
	VaultAuthJWTPath     = "VAULT_AUTH_JWT_PATH"
	VaultAuthJWTRole     = "VAULT_AUTH_JWT_ROLE"
	VaultAuthJWTHeader   = "VAULT_AUTH_JWT_HEADER"
	VaultAuthJWTCacheTTL = "VAULT_AUTH_JWT_CACHE_TTL"
)

const (
	defaultJWTAuthPath   = "jwt"
	defaultJWTAuthHeader = "Authorization"

	// cacheSafetyMargin keeps a cached token from being handed out right at
	// the edge of its lease expiry.
	cacheSafetyMargin = 10 * time.Second
)

// jwtAuthEnabled reports whether VAULT_AUTH_METHOD=jwt is configured.
func jwtAuthEnabled() bool {
	return strings.EqualFold(getEnv(VaultAuthMethod, "token"), "jwt")
}

// jwtAuthHeaderName returns the header the incoming JWT is read from.
func jwtAuthHeaderName() string {
	return getEnv(VaultAuthJWTHeader, defaultJWTAuthHeader)
}

// jwtLoginError is a JWT exchange failure carrying the HTTP status the
// caller should see. Acceptance criteria for this feature require that
// exchange failures are surfaced clearly rather than silently falling back
// to a static token, so this type is what the middleware inspects to pick
// the response status.
type jwtLoginError struct {
	status  int
	message string
}

func (e *jwtLoginError) Error() string   { return e.message }
func (e *jwtLoginError) StatusCode() int { return e.status }

// extractBearerToken pulls the JWT out of a header value such as
// "Bearer <token>". A bare token, with no "Bearer " prefix, is also
// accepted since some gateways forward the JWT without it.
func extractBearerToken(headerValue string) (string, error) {
	headerValue = strings.TrimSpace(headerValue)
	if headerValue == "" {
		return "", &jwtLoginError{http.StatusUnauthorized, fmt.Sprintf("missing JWT: %s header not provided", jwtAuthHeaderName())}
	}
	if rest, ok := strings.CutPrefix(headerValue, "Bearer "); ok {
		headerValue = strings.TrimSpace(rest)
	} else if strings.EqualFold(headerValue, "Bearer") {
		headerValue = ""
	}
	if headerValue == "" {
		return "", &jwtLoginError{http.StatusUnauthorized, "missing JWT: empty bearer token"}
	}
	return headerValue, nil
}

type cachedToken struct {
	token     string
	expiresAt time.Time
}

// jwtTokenCache maps sha256(jwt) to the Vault token obtained for it, so
// repeat requests within the token's lease don't re-hit /login.
var jwtTokenCache sync.Map

func cacheKey(jwt string) string {
	sum := sha256.Sum256([]byte(jwt))
	return hex.EncodeToString(sum[:])
}

func lookupCachedToken(jwt string) (string, bool) {
	key := cacheKey(jwt)
	value, ok := jwtTokenCache.Load(key)
	if !ok {
		return "", false
	}
	entry := value.(cachedToken)
	if time.Now().After(entry.expiresAt) {
		jwtTokenCache.Delete(key)
		return "", false
	}
	return entry.token, true
}

func storeCachedToken(jwt, vaultToken string, leaseDuration time.Duration) {
	if leaseDuration <= cacheSafetyMargin {
		// Lease too short to be worth caching; every request will just
		// exchange again.
		return
	}

	if cap := getEnv(VaultAuthJWTCacheTTL, ""); cap != "" {
		if capSeconds, err := strconv.Atoi(cap); err == nil {
			if capDuration := time.Duration(capSeconds) * time.Second; capDuration < leaseDuration {
				leaseDuration = capDuration
			}
		}
	}

	jwtTokenCache.Store(cacheKey(jwt), cachedToken{
		token:     vaultToken,
		expiresAt: time.Now().Add(leaseDuration - cacheSafetyMargin),
	})
}

// exchangeJWTForVaultToken calls Vault's JWT auth login endpoint and returns
// a short-lived, user-scoped Vault token plus its lease duration.
func exchangeJWTForVaultToken(vaultAddress, vaultNamespace string, vaultSkipTLSVerify bool, jwt string) (string, time.Duration, error) {
	role := getEnv(VaultAuthJWTRole, "")
	if role == "" {
		return "", 0, &jwtLoginError{http.StatusUnauthorized, "VAULT_AUTH_JWT_ROLE is not configured"}
	}
	mount := getEnv(VaultAuthJWTPath, defaultJWTAuthPath)

	loginClient, err := buildVaultClient(vaultAddress, vaultSkipTLSVerify, vaultNamespace)
	if err != nil {
		return "", 0, fmt.Errorf("failed to build Vault client for JWT login: %w", err)
	}

	secret, err := loginClient.Logical().Write(fmt.Sprintf("auth/%s/login", mount), map[string]interface{}{
		"role": role,
		"jwt":  jwt,
	})
	if err != nil {
		var respErr *api.ResponseError
		if errors.As(err, &respErr) {
			status := http.StatusUnauthorized
			if respErr.StatusCode == http.StatusForbidden {
				status = http.StatusForbidden
			}
			msg := "vault rejected the JWT"
			if len(respErr.Errors) > 0 {
				msg = strings.Join(respErr.Errors, "; ")
			}
			return "", 0, &jwtLoginError{status, msg}
		}
		// Not a Vault API error, e.g. the login request never reached
		// Vault. That's a connectivity problem, not an auth rejection.
		return "", 0, &jwtLoginError{http.StatusServiceUnavailable, fmt.Sprintf("could not reach Vault to exchange JWT: %v", err)}
	}
	if secret == nil || secret.Auth == nil || secret.Auth.ClientToken == "" {
		return "", 0, &jwtLoginError{http.StatusUnauthorized, "vault JWT login returned no token"}
	}

	return secret.Auth.ClientToken, time.Duration(secret.Auth.LeaseDuration) * time.Second, nil
}

// resolveJWTVaultToken returns a Vault token for the given JWT, using the
// in-memory cache when possible and exchanging with Vault otherwise.
func resolveJWTVaultToken(vaultAddress, vaultNamespace string, vaultSkipTLSVerify bool, jwt string, logger *log.Logger) (string, error) {
	if cached, ok := lookupCachedToken(jwt); ok {
		return cached, nil
	}

	vaultToken, leaseDuration, err := exchangeJWTForVaultToken(vaultAddress, vaultNamespace, vaultSkipTLSVerify, jwt)
	if err != nil {
		return "", err
	}

	storeCachedToken(jwt, vaultToken, leaseDuration)
	if logger != nil {
		logger.Debug("Vault token obtained via JWT exchange")
	}
	return vaultToken, nil
}
