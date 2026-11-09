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
	// DefaultRefreshInterval is how often the background loop checks the JWT expiry.
	DefaultRefreshInterval = 30 * time.Second
)

// TokenSource holds the current Delegation JWT and renews it in the background
// before it expires by re-running the STS token exchange for the same identity
// (no new browser login). The Subject access token is renewed via its refresh
// token when the IdP issued one; otherwise the cached access token is reused
// until it expires. The Actor is an OAuth client, so a fresh Actor token is
// obtained with the client credentials grant at every renewal. All tokens are
// kept in memory only.
//
// A nil *TokenSource is valid: Get returns nil, which keeps the VAULT_TOKEN
// fallback path (auth disabled) working unchanged.
type TokenSource struct {
	cfg AuthConfig

	interval time.Duration

	mu                  sync.RWMutex
	jwt                 *DelegationJWT
	subjectToken        string
	subjectRefreshToken string
	// actorToken is the most recent Actor access token. The Actor has no
	// refresh token (client credentials grant); it is kept only to revoke it.
	actorToken string
	closed     bool
	cancel     context.CancelFunc

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
// Subject tokens captured during the PKCE flow.
func NewTokenSource(cfg AuthConfig, jwt *DelegationJWT, pkce *PKCEResult) *TokenSource {
	s := &TokenSource{
		cfg:      cfg,
		interval: DefaultRefreshInterval,
		jwt:      jwt,
	}
	if pkce != nil {
		s.subjectToken = pkce.SubjectToken
		s.subjectRefreshToken = pkce.SubjectRefreshToken
		s.actorToken = pkce.ActorToken
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

// Revoke asks the IdP to revoke the Subject refresh token and the latest Actor
// access token (RFC 7009), in parallel. The Actor has no refresh token. Each
// token is revoked as its own application. It is best effort: both revocations
// are always attempted, errors are returned for logging and never contain
// token values, and the caller must still call Close.
func (s *TokenSource) Revoke() error {
	if s == nil || s.cfg.RevokeURL == "" {
		return ErrRevokeNotConfigured
	}
	s.mu.RLock()
	subjectRT, actorAT := s.subjectRefreshToken, s.actorToken
	s.mu.RUnlock()

	var subjectErr, actorErr error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		subjectErr = s.revokeToken(subjectRT, "refresh_token", s.cfg.SubjectPKCEConfig(), false)
	}()
	go func() {
		defer wg.Done()
		actorErr = s.revokeToken(actorAT, "access_token", s.cfg.ActorPKCEConfig(), true)
	}()
	wg.Wait()

	var errs []error
	if subjectErr != nil {
		errs = append(errs, fmt.Errorf("subject refresh token: %w", subjectErr))
	}
	if actorErr != nil {
		errs = append(errs, fmt.Errorf("actor access token: %w", actorErr))
	}
	return errors.Join(errs...)
}

// revokeToken posts an RFC 7009 revocation. With secretInBody the client
// authenticates with client_secret_post (as the Actor does at the token
// endpoint); otherwise a confidential client uses client_secret_basic and a
// public client sends only client_id.
func (s *TokenSource) revokeToken(token, hint string, cfg PKCEConfig, secretInBody bool) error {
	if token == "" {
		return nil
	}
	form := url.Values{}
	form.Set("token", token)
	form.Set("token_type_hint", hint)
	basic := cfg.ClientSecret != "" && !secretInBody
	if !basic {
		form.Set("client_id", cfg.ClientID)
		if secretInBody && cfg.ClientSecret != "" {
			form.Set("client_secret", cfg.ClientSecret)
		}
	}
	req, err := http.NewRequest(http.MethodPost, s.cfg.RevokeURL, strings.NewReader(form.Encode()))
	if err != nil {
		return errors.New("building revoke request")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basic {
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
	s.subjectToken, s.subjectRefreshToken, s.actorToken = "", "", ""
	s.onRefresh = nil
	s.onInvalidated = nil
}

// HasRefreshToken reports whether the IdP issued a refresh token for the Subject.
func (s *TokenSource) HasRefreshToken() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.subjectRefreshToken != ""
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
	haveTokens := s.subjectToken != ""
	if haveTokens {
		ctx, s.cancel = context.WithCancel(ctx)
	}
	s.mu.Unlock()
	if !haveTokens {
		fmt.Fprintf(os.Stderr, "[vault-mcp-server] No Subject token available; the Delegation JWT will not be renewed automatically\n")
		return
	}
	if !s.HasRefreshToken() {
		fmt.Fprintf(os.Stderr, "[vault-mcp-server] No Subject refresh token issued by the IdP; the Delegation JWT will be renewed with the cached Subject access token until it expires\n")
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

	// Refresh when 90% of the JWT lifetime has elapsed.
	window := current.Exp.Sub(current.Iat) * 10 / 100

	if time.Until(current.Exp) > window {
		return nil
	}

	subjectToken, err := s.subjectAccessToken()
	if err != nil {
		return fmt.Errorf("renewing Subject token: %w", err)
	}
	actor := ClientCredentialsGrant(s.cfg.ActorPKCEConfig())
	if actor.Err != nil {
		return fmt.Errorf("renewing Actor token: %w", actor.Err)
	}
	actorToken := actor.Token.AccessToken
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
	s.actorToken = actorToken
	onRefresh := s.onRefresh
	s.mu.Unlock()

	fmt.Fprintf(os.Stderr, "[vault-mcp-server] Delegation JWT refreshed (sub=%s, act=%s, exp=%s)\n", jwt.Sub, jwt.Act.Sub, jwt.Exp.Format(time.RFC3339))
	if onRefresh != nil {
		onRefresh(jwt)
	}
	return nil
}

// subjectAccessToken returns the Subject access token to use for the STS exchange.
// With a refresh token it fetches (and caches) a new access token, applying any
// rotated refresh token immediately so a later failure in the same cycle does not
// lose it. Without one it returns the cached access token.
func (s *TokenSource) subjectAccessToken() (string, error) {
	s.mu.RLock()
	if s.closed {
		s.mu.RUnlock()
		return "", context.Canceled
	}
	cached, rt := s.subjectToken, s.subjectRefreshToken
	s.mu.RUnlock()
	if rt == "" {
		return cached, nil
	}

	cfg := s.cfg.SubjectPKCEConfig()
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
	s.subjectToken = tok.AccessToken
	if tok.RefreshToken != "" {
		s.subjectRefreshToken = tok.RefreshToken
	}
	s.mu.Unlock()
	return tok.AccessToken, nil
}
