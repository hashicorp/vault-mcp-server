// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
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
	closed              bool
	cancel              context.CancelFunc

	// onRefresh, when set, is called with each newly issued JWT.
	onRefresh     func(*DelegationJWT)
	onInvalidated func()
}

// OnInvalidated registers session cleanup before the renewal loop starts.
func (s *TokenSource) OnInvalidated(fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onInvalidated = fn
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

// revokeTimeout bounds each revocation request at the IdP.
const revokeTimeout = 5 * time.Second

// ErrRevokeNotConfigured is returned by Revoke when no revocation URL is set.
var ErrRevokeNotConfigured = errors.New("revocation URL not configured")

// Revoke asks the IdP to revoke the Subject and Actor refresh tokens (RFC 7009).
// It is best effort: errors are returned for logging, never contain token
// values, and the caller must still call Close.
func (s *TokenSource) Revoke() error {
	if s == nil || s.cfg.RevokeURL == "" {
		return ErrRevokeNotConfigured
	}
	s.mu.RLock()
	subjectRT, actorRT := s.subjectRefreshToken, s.actorRefreshToken
	s.mu.RUnlock()

	var errs []error
	if err := s.revokeToken(subjectRT, s.cfg.SubjectPKCEConfig()); err != nil {
		errs = append(errs, fmt.Errorf("subject: %w", err))
	}
	if err := s.revokeToken(actorRT, s.cfg.ActorPKCEConfig()); err != nil {
		errs = append(errs, fmt.Errorf("actor: %w", err))
	}
	return errors.Join(errs...)
}

func (s *TokenSource) revokeToken(refreshToken string, cfg PKCEConfig) error {
	if refreshToken == "" {
		return nil
	}
	form := url.Values{}
	form.Set("token", refreshToken)
	form.Set("token_type_hint", "refresh_token")
	if cfg.ClientSecret == "" {
		form.Set("client_id", cfg.ClientID)
	}
	req, err := http.NewRequest(http.MethodPost, s.cfg.RevokeURL, strings.NewReader(form.Encode()))
	if err != nil {
		return errors.New("building revoke request")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if cfg.ClientSecret != "" {
		req.SetBasicAuth(cfg.ClientID, cfg.ClientSecret)
	}
	resp, err := (&http.Client{Timeout: revokeTimeout}).Do(req)
	if err != nil {
		return errors.New("revoke request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("revoke endpoint returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// Close stops renewal and drops references to session credentials.
// It is idempotent; Go does not guarantee physical erasure of string storage.
func (s *TokenSource) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	if s.cancel != nil {
		s.cancel()
		s.cancel = nil
	}
	s.jwt = nil
	s.subjectToken, s.actorToken = "", ""
	s.subjectRefreshToken, s.actorRefreshToken = "", ""
	s.onRefresh = nil
	s.onInvalidated = nil
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
	s.mu.Lock()
	if s.closed || s.cancel != nil {
		s.mu.Unlock()
		return
	}
	haveTokens := s.subjectToken != "" && s.actorToken != ""
	if haveTokens {
		ctx, s.cancel = context.WithCancel(ctx)
	}
	s.mu.Unlock()
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

	subjectToken, err := s.accessToken(&s.subjectToken, &s.subjectRefreshToken, s.cfg.SubjectPKCEConfig())
	if err != nil {
		return fmt.Errorf("renewing Subject token: %w", err)
	}
	actorToken, err := s.accessToken(&s.actorToken, &s.actorRefreshToken, s.cfg.ActorPKCEConfig())
	if err != nil {
		return fmt.Errorf("renewing Actor token: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	jwt, err := ExchangeTokens(subjectToken, actorToken, s.cfg.STSEndpoint, s.cfg.STSClientID, s.cfg.STSClientSecret, s.cfg.STSAuthorizationDetails)
	if err != nil {
		return fmt.Errorf("STS token exchange: %w", err)
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return context.Canceled
	}
	s.jwt = jwt
	onRefresh := s.onRefresh
	s.mu.Unlock()

	fmt.Fprintf(os.Stderr, "[vault-mcp-server] Delegation JWT refreshed (sub=%s, act=%s, exp=%s)\n", jwt.Sub, jwt.Act.Sub, jwt.Exp.Format(time.RFC3339))
	if onRefresh != nil {
		onRefresh(jwt)
	}
	return nil
}

// accessToken returns the access token to use for the STS exchange. With a refresh
// token it fetches (and caches) a new access token, applying any rotated refresh
// token immediately so a later failure in the same cycle does not lose it.
// Without one it returns the cached access token.
func (s *TokenSource) accessToken(token, refreshToken *string, cfg PKCEConfig) (string, error) {
	s.mu.RLock()
	if s.closed {
		s.mu.RUnlock()
		return "", context.Canceled
	}
	cached, rt := *token, *refreshToken
	s.mu.RUnlock()
	if rt == "" {
		return cached, nil
	}

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", rt)
	tok, err := postTokenForm(cfg.TokenURL, cfg.ClientID, cfg.ClientSecret, form)
	if err != nil {
		var oauthErr *oauthTokenError
		if errors.As(err, &oauthErr) && oauthErr.Code == "invalid_grant" {
			s.mu.RLock()
			onInvalidated := s.onInvalidated
			s.mu.RUnlock()
			s.Close()
			if onInvalidated != nil {
				onInvalidated()
			}
			return "", fmt.Errorf("re-authentication required: %w", err)
		}
		return "", err
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return "", context.Canceled
	}
	*token = tok.AccessToken
	if tok.RefreshToken != "" {
		*refreshToken = tok.RefreshToken
	}
	s.mu.Unlock()
	return tok.AccessToken, nil
}
