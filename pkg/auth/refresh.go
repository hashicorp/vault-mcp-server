// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package auth

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"sync"
	"time"
)

const (
	// DefaultRefreshWindow is the fixed fallback: how long before expiry the Delegation JWT is renewed.
	// refreshIfNeeded currently uses 10% of the JWT lifetime (Exp - Iat) instead.
	DefaultRefreshWindow = 870 * time.Second
	// DefaultRefreshInterval is how often the background loop checks the JWT expiry.
	DefaultRefreshInterval = 30 * time.Second
)

// TokenSource holds the current Delegation JWT and renews it in the background
// before it expires by re-running the STS token exchange for the same identity
// (no new browser login). The Subject and Actor access tokens are renewed via
// their refresh tokens when the IdP issued them; otherwise the cached access
// tokens are reused until they expire. All tokens are kept in memory only.
//
// A nil *TokenSource is valid: Get returns nil, which keeps the VAULT_TOKEN
// fallback path (auth disabled) working unchanged.
type TokenSource struct {
	cfg AuthConfig

	window   time.Duration
	interval time.Duration

	mu                  sync.RWMutex
	jwt                 *DelegationJWT
	subjectToken        string
	actorToken          string
	subjectRefreshToken string
	actorRefreshToken   string

	// onRefresh, when set, is called with each newly issued JWT.
	onRefresh func(*DelegationJWT)
}

// NewTokenSource returns a TokenSource seeded with the initial JWT and the
// refresh tokens captured during the PKCE flows.
func NewTokenSource(cfg AuthConfig, jwt *DelegationJWT, pkce *PKCEResult) *TokenSource {
	s := &TokenSource{
		cfg:      cfg,
		window:   DefaultRefreshWindow,
		interval: DefaultRefreshInterval,
		jwt:      jwt,
	}
	if pkce != nil {
		s.subjectToken = pkce.SubjectToken
		s.actorToken = pkce.ActorToken
		s.subjectRefreshToken = pkce.SubjectRefreshToken
		s.actorRefreshToken = pkce.ActorRefreshToken
	}
	return s
}

// OnRefresh registers a callback invoked after each successful refresh.
func (s *TokenSource) OnRefresh(fn func(*DelegationJWT)) {
	s.onRefresh = fn
}

// Get returns the current Delegation JWT. It is safe for concurrent use.
func (s *TokenSource) Get() *DelegationJWT {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.jwt
}

// DebugTokens returns the raw subject/actor access and refresh tokens.
// TEMPORARY: for local debugging only; remove before GA (AC-11, AC-14).
func (s *TokenSource) DebugTokens() (subject, subjectRefresh, actor, actorRefresh string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.subjectToken, s.subjectRefreshToken, s.actorToken, s.actorRefreshToken
}

// HasRefreshTokens reports whether the IdP issued refresh tokens for both identities.
func (s *TokenSource) HasRefreshTokens() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.subjectRefreshToken != "" && s.actorRefreshToken != ""
}

// Start runs the background refresh loop until ctx is cancelled. It returns
// immediately and does nothing when there are no tokens to renew from.
func (s *TokenSource) Start(ctx context.Context) {
	if s == nil {
		return
	}
	s.mu.RLock()
	haveTokens := s.subjectToken != "" && s.actorToken != ""
	s.mu.RUnlock()
	if !haveTokens {
		fmt.Fprintf(os.Stderr, "[vault-mcp-server] No Subject/Actor tokens available; the Delegation JWT will not be renewed automatically\n")
		return
	}
	if !s.HasRefreshTokens() {
		fmt.Fprintf(os.Stderr, "[vault-mcp-server] No refresh tokens issued by the IdP; the Delegation JWT will be renewed with the cached Subject/Actor access tokens until they expire\n")
	}

	go func() {
		ticker := time.NewTicker(s.interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := s.refreshIfNeeded(ctx); err != nil {
					fmt.Fprintf(os.Stderr, "[vault-mcp-server] Delegation JWT refresh failed: %v\n", err)
				}
			}
		}
	}()
}

// refreshIfNeeded renews the JWT when it is expired or within the refresh window.
func (s *TokenSource) refreshIfNeeded(ctx context.Context) error {
	current := s.Get()
	if current == nil || current.Exp.IsZero() {
		return nil
	}

	// Fixed window: refresh when less than s.window remains (default 870s).
	// window := s.window
	// Percentage-based window (future): refresh when 90% of JWT lifetime has elapsed.
	// Uncomment the line below and remove the fixed-window assignment above to switch.
	window := current.Exp.Sub(current.Iat) * 10 / 100

	if time.Until(current.Exp) > window {
		return nil
	}

	subjectToken, err := s.accessToken(&s.subjectToken, &s.subjectRefreshToken)
	if err != nil {
		return fmt.Errorf("renewing Subject token: %w", err)
	}
	actorToken, err := s.accessToken(&s.actorToken, &s.actorRefreshToken)
	if err != nil {
		return fmt.Errorf("renewing Actor token: %w", err)
	}

	// TEMPORARY debug logging of raw tokens; remove before GA (AC-11, AC-14).
	// _, subRT, _, actRT := s.DebugTokens()
	// fmt.Fprintf(os.Stderr, "[debug] refreshed subject_token=%s\n[debug] refreshed subject_refresh_token=%s\n[debug] refreshed actor_token=%s\n[debug] refreshed actor_refresh_token=%s\n", subjectToken, subRT, actorToken, actRT)

	jwt, err := ExchangeTokens(subjectToken, actorToken, s.cfg.STSEndpoint, s.cfg.STSClientID, s.cfg.STSClientSecret, s.cfg.STSAuthorizationDetails)
	if err != nil {
		return fmt.Errorf("STS token exchange: %w", err)
	}

	s.mu.Lock()
	s.jwt = jwt
	s.mu.Unlock()

	fmt.Fprintf(os.Stderr, "[vault-mcp-server] Delegation JWT refreshed (sub=%s, act=%s, exp=%s)\n", jwt.Sub, jwt.Act.Sub, jwt.Exp.Format(time.RFC3339))
	fmt.Fprintf(os.Stderr, "[vault-mcp-server] Delegation JWT refreshed (token=%s)\n", jwt.Raw)
	if s.onRefresh != nil {
		s.onRefresh(jwt)
	}
	return nil
}

// accessToken returns the access token to use for the STS exchange. With a refresh
// token it fetches (and caches) a new access token, applying any rotated refresh
// token immediately so a later failure in the same cycle does not lose it.
// Without one it returns the cached access token.
func (s *TokenSource) accessToken(token, refreshToken *string) (string, error) {
	s.mu.RLock()
	cached, rt := *token, *refreshToken
	s.mu.RUnlock()
	if rt == "" {
		return cached, nil
	}

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", rt)
	tok, err := postTokenForm(s.cfg.TokenURL, s.cfg.ClientID, s.cfg.ClientSecret, form)
	if err != nil {
		return "", err
	}

	s.mu.Lock()
	*token = tok.AccessToken
	if tok.RefreshToken != "" {
		*refreshToken = tok.RefreshToken
	}
	s.mu.Unlock()
	return tok.AccessToken, nil
}
