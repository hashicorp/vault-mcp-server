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
	// renewFraction and renewMinWindow set when a token is renewed: once the
	// time left drops to max(renewFraction of its lifetime, renewMinWindow). The
	// rule applies to the Delegation JWT and to the Subject and Actor access
	// tokens. A token whose whole lifetime is at most renewMinWindow is renewed
	// on every call, because it is inside the window from the moment it is issued.
	renewFraction  = 10 // percent
	renewMinWindow = 60 * time.Second
)

// ErrReauthRequired means the session can no longer be renewed and the user
// must sign in again with vault_login.
var ErrReauthRequired = errors.New("re-authentication required")

// TokenSource holds the current Delegation JWT and renews it on demand, when
// Token finds it close to expiry, by re-running the STS token exchange for the
// same identity (no new browser login). The Subject access token is renewed via
// its refresh token when it is close to expiry. The Actor is an OAuth client, so
// a new Actor token is obtained with the client credentials grant when needed.
// All tokens are kept in memory only.
//
// A nil *TokenSource is valid: Get and Token return nil, which keeps the
// VAULT_TOKEN fallback path (auth disabled) working unchanged.
type TokenSource struct {
	cfg AuthConfig

	// renewSlot is a one-slot lock that lets a single renewal run at a time and,
	// unlike a sync.Mutex, lets a waiting caller give up when its context ends.
	// A send acquires it and a receive releases it. Callers that waited find the
	// JWT already renewed, and a rotated Subject refresh token is never used twice.
	renewSlot chan struct{}

	// mu guards every field below. Get, Revoke, Close and the renewal steps all
	// touch them from different goroutines. It is never held across a network call.
	mu                  sync.RWMutex
	jwt                 *DelegationJWT
	subjectToken        string
	subjectRefreshToken string
	subjectIssuedAt     time.Time
	subjectExpiresAt    time.Time
	// actorToken is the most recent Actor access token. The Actor has no
	// refresh token (client credentials grant); it is reused until it is close
	// to expiry and kept to revoke it.
	actorToken     string
	actorIssuedAt  time.Time
	actorExpiresAt time.Time
	closed         bool
	onInvalidated  func()
}

// OnInvalidated registers a callback that runs once when renewal can no longer
// succeed without a new sign-in. The login layer uses it to move to
// reauthRequired and drop the cached Vault clients; the MCP session itself stays
// open.
func (s *TokenSource) OnInvalidated(fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onInvalidated = fn
}

// NewTokenSource returns a TokenSource seeded with the initial JWT and the
// Subject and Actor tokens captured during login.
func NewTokenSource(cfg AuthConfig, jwt *DelegationJWT, pkce *PKCEResult) *TokenSource {
	s := &TokenSource{
		cfg:       cfg,
		jwt:       jwt,
		renewSlot: make(chan struct{}, 1),
	}
	if pkce != nil {
		s.subjectToken = pkce.SubjectToken
		s.subjectRefreshToken = pkce.SubjectRefreshToken
		s.subjectIssuedAt, s.subjectExpiresAt = pkce.SubjectIssuedAt, pkce.SubjectExpiresAt
		s.actorToken = pkce.ActorToken
		s.actorIssuedAt, s.actorExpiresAt = pkce.ActorIssuedAt, pkce.ActorExpiresAt
	}
	return s
}

// needsRenewal reports whether a token issued at issued that expires at
// expiresAt is inside its renewal window. An unknown expiry always needs renewal.
func needsRenewal(issued, expiresAt time.Time) bool {
	if expiresAt.IsZero() {
		return true
	}
	lifetime := expiresAt.Sub(issued)
	window := max(lifetime*renewFraction/100, renewMinWindow)
	return time.Until(expiresAt) <= window
}

// jwtNeedsRenewal is needsRenewal for the Delegation JWT. exp is optional in
// RFC 7519; the IBM Verify STS always sets it, but a JWT without it is treated
// as non-expiring so a missing claim does not cause a renewal on every call.
func jwtNeedsRenewal(jwt *DelegationJWT) bool {
	return !jwt.Exp.IsZero() && needsRenewal(jwt.Iat, jwt.Exp)
}

// Get returns the current Delegation JWT without renewing it. It is safe for
// concurrent use.
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
//
// Known limitation: Revoke does not wait for a renewal that is in flight. If the
// IdP rotates the Subject refresh token during that renewal, the new token is
// discarded by Close without having been revoked and stays valid at the IdP until
// it expires. To be handled when the revoke flow is reworked.
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

// Close drops references to session credentials; later Token calls return nil.
// It is idempotent; Go does not guarantee physical erasure of string storage.
func (s *TokenSource) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	s.jwt = nil
	s.subjectToken, s.subjectRefreshToken, s.actorToken = "", "", ""
	s.onInvalidated = nil
}

// Token returns the current Delegation JWT, renewing it first when it is inside
// its renewal window. It returns (nil, nil) for a nil or closed source, which
// callers treat as "not signed in". Renewal is single-flight: concurrent callers
// wait for one renewal and share its result. It returns ErrReauthRequired when
// the user has to sign in again.
//
// A failed renewal fails the call even if the current JWT is still valid.
// Future enhancement: keep serving the current JWT until it really expires when
// the failure is transient (network error, 5xx), and only fail on definitive
// ones such as invalid_grant.
func (s *TokenSource) Token(ctx context.Context) (*DelegationJWT, error) {
	if s == nil {
		return nil, nil
	}
	if jwt := s.Get(); jwt == nil || !jwtNeedsRenewal(jwt) {
		return jwt, nil
	}

	// Take the renewal slot, or give up if the caller's context ends first.
	select {
	case s.renewSlot <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-s.renewSlot }()

	// Another caller may have renewed while this one waited.
	if jwt := s.Get(); jwt == nil || !jwtNeedsRenewal(jwt) {
		return jwt, nil
	}
	return s.renew()
}

// renew runs the Subject refresh, the Actor grant and the STS exchange. It does
// not take the caller's context: abandoning it midway could lose a rotated
// refresh token. Each IdP and STS request is bounded by httpTimeout instead.
func (s *TokenSource) renew() (*DelegationJWT, error) {
	subjectToken, err := s.subjectAccessToken()
	if err != nil {
		return nil, fmt.Errorf("renewing Subject token: %w", err)
	}
	actorToken, err := s.actorAccessToken()
	if err != nil {
		return nil, fmt.Errorf("renewing Actor token: %w", err)
	}

	jwt, err := ExchangeTokens(subjectToken, actorToken, s.cfg.STSEndpoint, s.cfg.STSClientID, s.cfg.STSClientSecret, s.cfg.STSAuthorizationDetails)
	if err != nil {
		return nil, fmt.Errorf("STS token exchange: %w", err)
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, context.Canceled
	}
	s.jwt = jwt
	s.mu.Unlock()

	fmt.Fprintf(os.Stderr, "[vault-mcp-server] Delegation JWT renewed (sub=%s, act=%s, exp=%s)\n", jwt.Sub, jwt.Act.Sub, jwt.Exp.Format(time.RFC3339))
	return jwt, nil
}

// actorAccessToken returns the Actor access token for the STS exchange, getting
// a new one with the client credentials grant when the current one is close to
// expiry.
func (s *TokenSource) actorAccessToken() (string, error) {
	// Copy what is needed under the lock and release it before the network call,
	// so Get, Close and Revoke are never blocked by a slow IdP.
	s.mu.RLock()
	if s.closed {
		s.mu.RUnlock()
		return "", context.Canceled
	}
	cached, issuedAt, expiresAt := s.actorToken, s.actorIssuedAt, s.actorExpiresAt
	s.mu.RUnlock()
	if cached != "" && !needsRenewal(issuedAt, expiresAt) {
		return cached, nil
	}

	actor := ClientCredentialsGrant(s.cfg.ActorPKCEConfig())
	if actor.Err != nil {
		return "", actor.Err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	// The session may have been closed while the request was in flight.
	if s.closed {
		return "", context.Canceled
	}
	s.actorToken = actor.Token.AccessToken
	s.actorIssuedAt, s.actorExpiresAt = actor.Token.IssuedAt, actor.Token.ExpiresAt
	return s.actorToken, nil
}

// subjectAccessToken returns the Subject access token to use for the STS exchange.
// The cached token is reused while it is outside its renewal window. Otherwise a
// refresh token fetches a new one, and any rotated refresh token is stored
// immediately so a later failure in the same renewal does not lose it. Without a
// refresh token the cached token is used until it expires, then the user must
// sign in again.
func (s *TokenSource) subjectAccessToken() (string, error) {
	s.mu.RLock()
	if s.closed {
		s.mu.RUnlock()
		return "", context.Canceled
	}
	cached, rt := s.subjectToken, s.subjectRefreshToken
	issuedAt, expiresAt := s.subjectIssuedAt, s.subjectExpiresAt
	s.mu.RUnlock()
	if cached != "" && !needsRenewal(issuedAt, expiresAt) {
		return cached, nil
	}
	if rt == "" {
		if cached != "" && (expiresAt.IsZero() || time.Now().Before(expiresAt)) {
			return cached, nil
		}
		return "", s.invalidate(errors.New("subject access token expired and the IdP issued no refresh token"))
	}

	cfg := s.cfg.SubjectPKCEConfig()
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", rt)
	tok, err := postTokenForm(cfg.TokenURL, cfg.ClientID, cfg.ClientSecret, form)
	if err != nil {
		var oauthErr *oauthTokenError
		if errors.As(err, &oauthErr) && oauthErr.Code == "invalid_grant" {
			return "", s.invalidate(err)
		}
		return "", err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return "", context.Canceled
	}
	s.subjectToken = tok.AccessToken
	if tok.RefreshToken != "" {
		s.subjectRefreshToken = tok.RefreshToken
	}
	s.subjectIssuedAt, s.subjectExpiresAt = tok.IssuedAt, tok.ExpiresAt
	return tok.AccessToken, nil
}

// invalidate ends the session after a failure that only a new sign-in can fix
// and returns an error wrapping ErrReauthRequired.
func (s *TokenSource) invalidate(cause error) error {
	s.mu.RLock()
	onInvalidated := s.onInvalidated
	s.mu.RUnlock()
	s.Close()
	if onInvalidated != nil {
		onInvalidated()
	}
	return fmt.Errorf("%w: %w", ErrReauthRequired, cause)
}
