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

	log "github.com/sirupsen/logrus"
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
	// logger reports revocation outcomes. Nil means they are not logged.
	logger *log.Logger

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

// WithLogger sets the logger used to report the outcome of each token
// revocation, and returns s. Without this call, outcomes are not logged. Call it
// before the source is shared.
func (s *TokenSource) WithLogger(logger *log.Logger) *TokenSource {
	s.logger = logger
	return s
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

// tokenSnapshot is the set of tokens to revoke, taken when the source is closed.
type tokenSnapshot struct {
	subjectRefresh, subjectAccess, actorAccess string
}

// Revoke asks the IdP to revoke the session's tokens (RFC 7009), logs the
// outcome of each, and closes the source. The Subject refresh token is revoked if
// one is held; the Subject access token only when there is no refresh token or
// the refresh token revocation failed. The Actor has no refresh token, so its
// latest access token is revoked. The Subject and the Actor are revoked in
// parallel, each as its own application. It is best effort: failures are logged,
// never returned.
//
// Revoke first waits, without a time limit, for any renewal in flight (a renewal
// is bounded by httpTimeout per request), so a refresh token rotated by that
// renewal is the one revoked.
func (s *TokenSource) Revoke() {
	if s == nil {
		return
	}
	s.renewSlot <- struct{}{}
	snap := s.closeAndSnapshot()
	<-s.renewSlot

	s.revokeSnapshot(snap)
}

// revokeSnapshot revokes the tokens in snap. It does not touch renewSlot, so the
// invalidation path, which runs inside a renewal, can call it.
func (s *TokenSource) revokeSnapshot(snap tokenSnapshot) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		cfg := s.cfg.SubjectPKCEConfig()
		if snap.subjectRefresh != "" && s.revokeOne("subject_refresh_token", snap.subjectRefresh, "refresh_token", cfg, false) == nil {
			return
		}
		s.revokeOne("subject_access_token", snap.subjectAccess, "access_token", cfg, false)
	}()
	go func() {
		defer wg.Done()
		s.revokeOne("actor_access_token", snap.actorAccess, "access_token", s.cfg.ActorPKCEConfig(), true)
	}()
	wg.Wait()
}

// revokeOne revokes a single token and logs the outcome. It returns the
// revocation error, or nil when the token was revoked or skipped.
func (s *TokenSource) revokeOne(name, token, hint string, cfg PKCEConfig, secretInBody bool) error {
	if reason := s.skipReason(token); reason != "" {
		s.logOutcome(name, "skipped", reason)
		return nil
	}
	if err := s.revokeToken(token, hint, cfg, secretInBody); err != nil {
		s.logOutcome(name, "failed", err.Error())
		return err
	}
	s.logOutcome(name, "revoked", "")
	return nil
}

// skipReason says why a token is not revoked, or returns "" if it should be.
func (s *TokenSource) skipReason(token string) string {
	switch {
	case token == "":
		return "no token held"
	case s.cfg.RevokeURL == "":
		return "revocation URL not configured"
	}
	return ""
}

// logOutcome logs the token's name, the outcome and a short reason. It never
// logs a token value.
func (s *TokenSource) logOutcome(name, outcome, reason string) {
	if s.logger == nil {
		return
	}
	entry := s.logger.WithFields(log.Fields{"token": name, "outcome": outcome})
	if reason != "" {
		entry = entry.WithField("reason", reason)
	}
	if outcome == "failed" {
		entry.Warn("Token revocation at IdP failed; discarding credentials anyway")
		return
	}
	entry.Info("Token revocation at IdP")
}

// revokeToken posts an RFC 7009 revocation. With secretInBody the client
// authenticates with client_secret_post (as the Actor does at the token
// endpoint); otherwise a confidential client uses client_secret_basic and a
// public client sends only client_id.
func (s *TokenSource) revokeToken(token, hint string, cfg PKCEConfig, secretInBody bool) error {
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
	s.closeAndSnapshot()
}

// closeAndSnapshot closes the source like Close and returns the tokens it held,
// so they can still be revoked.
func (s *TokenSource) closeAndSnapshot() tokenSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := tokenSnapshot{s.subjectRefreshToken, s.subjectToken, s.actorToken}
	s.closed = true
	s.jwt = nil
	s.subjectToken, s.subjectRefreshToken, s.actorToken = "", "", ""
	s.onInvalidated = nil
	return snap
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

// invalidate ends the session after a failure that only a new sign-in can fix,
// revokes its tokens at the IdP and returns an error wrapping ErrReauthRequired.
// It runs inside a renewal, which already holds renewSlot, so it must not wait
// for the slot.
func (s *TokenSource) invalidate(cause error) error {
	s.mu.RLock()
	onInvalidated := s.onInvalidated
	s.mu.RUnlock()
	s.revokeSnapshot(s.closeAndSnapshot())
	if onInvalidated != nil {
		onInvalidated()
	}
	return fmt.Errorf("%w: %w", ErrReauthRequired, cause)
}
