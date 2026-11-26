// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package auth

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// refreshFixture wires a fake IdP token endpoint (refresh_token grant for the
// Subject, client_credentials grant for the Actor) and a fake STS endpoint that
// returns newJWT.
type refreshFixture struct {
	cfg         AuthConfig
	idpCalls    atomic.Int32
	actorCalls  atomic.Int32
	stsCalls    atomic.Int32
	idpStatus   int
	actorStatus int
	stsStatus   int
	stsDelay    time.Duration
	refreshIDs  []string
	clientIDs   []string
	secrets     []string
}

func newRefreshFixture(t *testing.T, newJWT string) *refreshFixture {
	t.Helper()
	f := &refreshFixture{idpStatus: http.StatusOK, actorStatus: http.StatusOK}

	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		w.Header().Set("Content-Type", "application/json")
		if r.PostForm.Get("grant_type") == "client_credentials" {
			f.actorCalls.Add(1)
			_, _, basic := r.BasicAuth()
			assert.False(t, basic, "actor must use client_secret_post")
			f.clientIDs = append(f.clientIDs, r.PostForm.Get("client_id"))
			f.secrets = append(f.secrets, r.PostForm.Get("client_secret"))
			if f.actorStatus != http.StatusOK {
				http.Error(w, `{"error":"invalid_client"}`, f.actorStatus)
				return
			}
			fmt.Fprint(w, `{"access_token":"actor-access","expires_in":3600}`)
			return
		}
		assert.Equal(t, "refresh_token", r.PostForm.Get("grant_type"))
		n := f.idpCalls.Add(1)
		f.refreshIDs = append(f.refreshIDs, r.PostForm.Get("refresh_token"))
		id, secret, basic := r.BasicAuth()
		if !basic {
			id = r.PostForm.Get("client_id")
		}
		f.clientIDs = append(f.clientIDs, id)
		f.secrets = append(f.secrets, secret)
		if f.idpStatus != http.StatusOK {
			http.Error(w, `{"error":"invalid_grant"}`, f.idpStatus)
			return
		}
		fmt.Fprintf(w, `{"access_token":"subject-access","refresh_token":"rotated-%d","expires_in":3600}`, n)
	}))
	t.Cleanup(idp.Close)

	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		assert.Equal(t, "subject-access", r.PostForm.Get("subject_token"))
		assert.Equal(t, "actor-access", r.PostForm.Get("actor_token"))
		f.stsCalls.Add(1)
		time.Sleep(f.stsDelay)
		if f.stsStatus != 0 {
			http.Error(w, "sts unavailable", f.stsStatus)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":%q}`, newJWT)
	}))
	t.Cleanup(sts.Close)

	f.cfg = AuthConfig{
		Enabled:           true,
		SubjectClientID:   "subject-app",
		ActorClientID:     "actor-app",
		ActorClientSecret: "actor-secret",
		TokenURL:          idp.URL,
		STSEndpoint:       sts.URL,
	}
	return f
}

// nearExpiry returns the issue and expiry times of a token issued an hour ago
// with 30s left, which is inside its renewal window.
func nearExpiry() (issuedAt, expiresAt time.Time) {
	now := time.Now()
	return now.Add(-time.Hour), now.Add(30 * time.Second)
}

func initialJWT(t *testing.T, exp time.Time) *DelegationJWT {
	t.Helper()
	jwt, err := ParseUnsigned(buildDelegationJWT(t, "user@example.com", "mcp-server", exp.Unix()))
	require.NoError(t, err)
	// Test JWTs carry no iat claim; model a 2h lifetime so the 10% refresh window is 12m.
	jwt.Iat = exp.Add(-2 * time.Hour)
	return jwt
}

// A second Revoke, like Revoke after invalidation, makes no request and logs
// nothing: the tokens were already revoked when the source was first closed.
func TestTokenSource_RevokeIsIdempotent(t *testing.T) {
	f := newRefreshFixture(t, "unused")
	url, calls := newRevokeRecorder(t)
	f.cfg.RevokeURL = url
	logger, hook := test.NewNullLogger()
	ts := NewTokenSource(f.cfg, initialJWT(t, time.Now().Add(time.Minute)),
		&PKCEResult{SubjectToken: "subject", SubjectRefreshToken: "srt"}).WithLogger(logger)

	ts.Revoke()
	first := len(hook.AllEntries())
	ts.Revoke()

	assert.Len(t, calls(), 1)
	assert.Len(t, hook.AllEntries(), first, "the second Revoke logs nothing")
	assert.Nil(t, ts.Get())
	assert.Empty(t, ts.subjectToken)
	assert.Empty(t, ts.subjectRefreshToken)
	jwt, err := ts.Token(context.Background())
	require.NoError(t, err)
	assert.Nil(t, jwt)
	assert.Zero(t, f.idpCalls.Load())
	assert.Zero(t, f.actorCalls.Load())
}

// A JWT without exp does not expire, so it is never renewed.
func TestTokenSource_JWTWithoutExpIsNotRenewed(t *testing.T) {
	f := newRefreshFixture(t, "unused")
	jwt, err := ParseUnsigned(buildDelegationJWT(t, "user@example.com", "mcp-server", 0))
	require.NoError(t, err)
	ts := NewTokenSource(f.cfg, jwt, &PKCEResult{SubjectRefreshToken: "srt"})

	got, err := ts.Token(context.Background())

	require.NoError(t, err)
	assert.Same(t, jwt, got)
	assert.Zero(t, f.idpCalls.Load()+f.actorCalls.Load()+f.stsCalls.Load())
}

func TestTokenSource_RenewsWithinWindow(t *testing.T) {
	newRaw := buildDelegationJWT(t, "user@example.com", "mcp-server", time.Now().Add(15*time.Minute).Unix())
	f := newRefreshFixture(t, newRaw)

	ts := NewTokenSource(f.cfg, initialJWT(t, time.Now().Add(time.Minute)),
		&PKCEResult{SubjectRefreshToken: "subject-rt"})

	jwt, err := ts.Token(context.Background())

	require.NoError(t, err)
	assert.Equal(t, newRaw, jwt.Raw)
	assert.Equal(t, newRaw, ts.Get().Raw)
	assert.Equal(t, []string{"subject-rt"}, f.refreshIDs)
	assert.Equal(t, []string{"subject-app", "actor-app"}, f.clientIDs)
	assert.EqualValues(t, 1, f.actorCalls.Load())
	assert.EqualValues(t, 1, f.stsCalls.Load())
	// The rotated refresh token replaces the original.
	assert.Equal(t, "rotated-1", ts.subjectRefreshToken)
}

func TestTokenSource_RenewsWithSeparateApplications(t *testing.T) {
	f := newRefreshFixture(t, buildDelegationJWT(t, "user", "actor", time.Now().Add(time.Hour).Unix()))
	f.cfg.SubjectClientID, f.cfg.SubjectClientSecret = "subject-app", "subject-secret"
	f.cfg.ActorClientID, f.cfg.ActorClientSecret = "actor-app", "actor-secret"
	ts := NewTokenSource(f.cfg, initialJWT(t, time.Now().Add(time.Minute)),
		&PKCEResult{SubjectRefreshToken: "subject-rt"})

	_, err := ts.Token(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []string{"subject-app", "actor-app"}, f.clientIDs)
	assert.Equal(t, []string{"subject-secret", "actor-secret"}, f.secrets)
	assert.Equal(t, []string{"subject-rt"}, f.refreshIDs)
}

func TestTokenSource_RenewsAlreadyExpiredJWT(t *testing.T) {
	newRaw := buildDelegationJWT(t, "user@example.com", "mcp-server", time.Now().Add(15*time.Minute).Unix())
	f := newRefreshFixture(t, newRaw)

	// ParseUnsigned rejects expired tokens, so build the expired JWT directly.
	expired := &DelegationJWT{Sub: "user@example.com", Exp: time.Now().Add(-10 * time.Hour), Raw: "old"}
	ts := NewTokenSource(f.cfg, expired, &PKCEResult{SubjectRefreshToken: "s"})

	jwt, err := ts.Token(context.Background())

	require.NoError(t, err)
	assert.Equal(t, newRaw, jwt.Raw)
}

func TestTokenSource_SkipsWhenFarFromExpiry(t *testing.T) {
	f := newRefreshFixture(t, "unused")
	jwt := initialJWT(t, time.Now().Add(time.Hour))
	ts := NewTokenSource(f.cfg, jwt, &PKCEResult{SubjectRefreshToken: "s"})

	got, err := ts.Token(context.Background())

	require.NoError(t, err)
	assert.Same(t, jwt, got)
	assert.EqualValues(t, 0, f.idpCalls.Load())
	assert.EqualValues(t, 0, f.actorCalls.Load())
	assert.EqualValues(t, 0, f.stsCalls.Load())
}

// A failed renewal fails the call even though the current JWT is still valid.
func TestTokenSource_TransientFailureReturnsError(t *testing.T) {
	f := newRefreshFixture(t, "unused")
	f.idpStatus = http.StatusServiceUnavailable
	jwt := initialJWT(t, time.Now().Add(time.Minute))
	ts := NewTokenSource(f.cfg, jwt, &PKCEResult{SubjectRefreshToken: "s"})
	invalidated := false
	ts.OnInvalidated(func() { invalidated = true })

	got, err := ts.Token(context.Background())

	require.Error(t, err)
	assert.Nil(t, got)
	assert.NotErrorIs(t, err, ErrReauthRequired)
	assert.Contains(t, err.Error(), "Subject")
	assert.False(t, invalidated)
	assert.Same(t, jwt, ts.Get())
	assert.EqualValues(t, 0, f.stsCalls.Load())
}

func TestTokenSource_InvalidGrantRequiresReauthentication(t *testing.T) {
	var idpCalls atomic.Int32
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		idpCalls.Add(1)
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"error":"invalid_grant"}`)
	}))
	t.Cleanup(idp.Close)
	revokeURL, calls := newRevokeRecorder(t)
	logger, hook := test.NewNullLogger()
	ts := NewTokenSource(AuthConfig{TokenURL: idp.URL, RevokeURL: revokeURL}, initialJWT(t, time.Now().Add(time.Minute)),
		&PKCEResult{SubjectToken: "subject", SubjectRefreshToken: "subject-rt", ActorToken: "actor-at"}).WithLogger(logger)
	invalidated := false
	ts.OnInvalidated(func() { invalidated = true })

	_, err := ts.Token(context.Background())

	require.ErrorIs(t, err, ErrReauthRequired)
	assert.True(t, invalidated)
	assert.Nil(t, ts.Get())
	assert.Empty(t, ts.subjectRefreshToken)
	assert.Empty(t, ts.subjectToken)
	// Invalidation revokes what the session still holds.
	assert.ElementsMatch(t, []string{"subject-rt", "actor-at"}, revokedTokens(calls()))

	// Later calls keep asking for a new sign-in without contacting the IdP, and
	// the revocation at session end has nothing left to do.
	logged := len(hook.AllEntries())
	_, err = ts.Token(context.Background())
	require.ErrorIs(t, err, ErrReauthRequired)
	ts.Revoke()
	assert.EqualValues(t, 1, idpCalls.Load())
	assert.Len(t, calls(), 2)
	assert.Len(t, hook.AllEntries(), logged)
}

// A rejected actor client is a configuration problem: the JWT is kept and no
// re-authentication is requested.
func TestTokenSource_ActorClientFailureKeepsSession(t *testing.T) {
	f := newRefreshFixture(t, "unused")
	f.actorStatus = http.StatusUnauthorized
	jwt := initialJWT(t, time.Now().Add(time.Minute))
	ts := NewTokenSource(f.cfg, jwt, &PKCEResult{SubjectRefreshToken: "s"})
	invalidated := false
	ts.OnInvalidated(func() { invalidated = true })

	_, err := ts.Token(context.Background())

	require.ErrorContains(t, err, "Actor")
	assert.NotErrorIs(t, err, ErrReauthRequired)
	assert.False(t, invalidated)
	assert.Same(t, jwt, ts.Get())
	assert.EqualValues(t, 0, f.stsCalls.Load())
}

// The rotated refresh token must survive a failure later in the same renewal.
func TestTokenSource_RotatedRefreshTokenSurvivesSTSFailure(t *testing.T) {
	f := newRefreshFixture(t, "unused")
	f.stsStatus = http.StatusBadGateway
	ts := NewTokenSource(f.cfg, initialJWT(t, time.Now().Add(time.Minute)),
		&PKCEResult{SubjectRefreshToken: "subject-rt"})

	_, err := ts.Token(context.Background())

	require.Error(t, err)
	assert.Equal(t, "rotated-1", ts.subjectRefreshToken)
}

func TestTokenSource_Nil(t *testing.T) {
	var nilSource *TokenSource
	assert.Nil(t, nilSource.Get())
	jwt, err := nilSource.Token(context.Background())
	require.NoError(t, err)
	assert.Nil(t, jwt)
}

// Subject and Actor tokens that are well outside their window are reused.
func TestTokenSource_ReusesTokensOutsideTheirWindow(t *testing.T) {
	newRaw := buildDelegationJWT(t, "user@example.com", "mcp-server", time.Now().Add(15*time.Minute).Unix())
	f := newRefreshFixture(t, newRaw)
	now := time.Now()
	ts := NewTokenSource(f.cfg, initialJWT(t, time.Now().Add(time.Minute)), &PKCEResult{
		SubjectToken: "subject-access", SubjectRefreshToken: "subject-rt",
		SubjectIssuedAt: now, SubjectExpiresAt: now.Add(time.Hour),
		ActorToken:    "actor-access",
		ActorIssuedAt: now, ActorExpiresAt: now.Add(time.Hour),
	})

	_, err := ts.Token(context.Background())

	require.NoError(t, err)
	assert.EqualValues(t, 0, f.idpCalls.Load())
	assert.EqualValues(t, 0, f.actorCalls.Load())
	assert.EqualValues(t, 1, f.stsCalls.Load())
}

func TestTokenSource_RenewsTokensInsideTheirWindow(t *testing.T) {
	newRaw := buildDelegationJWT(t, "user@example.com", "mcp-server", time.Now().Add(15*time.Minute).Unix())
	f := newRefreshFixture(t, newRaw)
	ts := NewTokenSource(f.cfg, initialJWT(t, time.Now().Add(time.Minute)), &PKCEResult{
		SubjectToken: "old-subject", SubjectRefreshToken: "subject-rt",
		ActorToken: "old-actor",
	})
	// Issued an hour ago, 30s left: inside the 6 minute window.
	ts.subjectIssuedAt, ts.subjectExpiresAt = nearExpiry()
	ts.actorIssuedAt, ts.actorExpiresAt = nearExpiry()

	_, err := ts.Token(context.Background())

	require.NoError(t, err)
	assert.EqualValues(t, 1, f.idpCalls.Load())
	assert.EqualValues(t, 1, f.actorCalls.Load())
	// expires_in from the new responses is tracked.
	assert.WithinDuration(t, time.Now().Add(time.Hour), ts.subjectExpiresAt, 5*time.Second)
	assert.WithinDuration(t, time.Now().Add(time.Hour), ts.actorExpiresAt, 5*time.Second)
}

func TestTokenSource_NoRefreshToken(t *testing.T) {
	newRaw := buildDelegationJWT(t, "user@example.com", "mcp-server", time.Now().Add(15*time.Minute).Unix())

	t.Run("still valid inside window is reused", func(t *testing.T) {
		f := newRefreshFixture(t, newRaw)
		now := time.Now()
		ts := NewTokenSource(f.cfg, initialJWT(t, time.Now().Add(time.Minute)),
			&PKCEResult{SubjectToken: "subject-access", ActorToken: "actor-access", ActorIssuedAt: now, ActorExpiresAt: now.Add(time.Hour)})
		ts.subjectIssuedAt, ts.subjectExpiresAt = nearExpiry()

		_, err := ts.Token(context.Background())

		require.NoError(t, err)
		assert.EqualValues(t, 0, f.idpCalls.Load())
		assert.EqualValues(t, 1, f.stsCalls.Load())
	})

	t.Run("expired requires re-authentication", func(t *testing.T) {
		f := newRefreshFixture(t, newRaw)
		ts := NewTokenSource(f.cfg, initialJWT(t, time.Now().Add(time.Minute)),
			&PKCEResult{SubjectToken: "subject-access"})
		ts.subjectIssuedAt, ts.subjectExpiresAt = time.Now().Add(-time.Hour), time.Now().Add(-time.Second)
		invalidated := false
		ts.OnInvalidated(func() { invalidated = true })

		_, err := ts.Token(context.Background())

		require.ErrorIs(t, err, ErrReauthRequired)
		assert.True(t, invalidated)
		assert.Nil(t, ts.Get())
		assert.EqualValues(t, 0, f.stsCalls.Load())
	})
}

func TestTokenSource_ConcurrentCallsRenewOnce(t *testing.T) {
	newRaw := buildDelegationJWT(t, "user@example.com", "mcp-server", time.Now().Add(15*time.Minute).Unix())
	f := newRefreshFixture(t, newRaw)
	f.stsDelay = 100 * time.Millisecond
	ts := NewTokenSource(f.cfg, initialJWT(t, time.Now().Add(time.Minute)),
		&PKCEResult{SubjectRefreshToken: "subject-rt"})

	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			jwt, err := ts.Token(context.Background())
			assert.NoError(t, err)
			assert.Equal(t, newRaw, jwt.Raw)
		}()
	}
	wg.Wait()

	assert.EqualValues(t, 1, f.idpCalls.Load())
	assert.EqualValues(t, 1, f.stsCalls.Load())
}

// A caller that gives up while waiting for a renewal in progress returns at once.
func TestTokenSource_WaiterHonoursContext(t *testing.T) {
	f := newRefreshFixture(t, "unused")
	jwt := initialJWT(t, time.Now().Add(time.Minute))
	ts := NewTokenSource(f.cfg, jwt, &PKCEResult{SubjectRefreshToken: "s"})
	ts.renewSlot <- struct{}{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := ts.Token(ctx)

	require.ErrorIs(t, err, context.Canceled)
	assert.Zero(t, f.idpCalls.Load())
}

func TestNeedsRenewal(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name     string
		lifetime time.Duration
		left     time.Duration
		want     bool
	}{
		{"1h token with 7m left", time.Hour, 7 * time.Minute, false},
		{"1h token with 5m left", time.Hour, 5 * time.Minute, true},
		{"10m token keeps a 60s minimum window", 10 * time.Minute, 70 * time.Second, false},
		{"10m token inside the 60s minimum window", 10 * time.Minute, 50 * time.Second, true},
		{"90s token waits for the 60s window", 90 * time.Second, 70 * time.Second, false},
		{"90s token inside the 60s window", 90 * time.Second, 50 * time.Second, true},
		{"token no longer than the window renews immediately", time.Minute, 59 * time.Second, true},
		{"already expired", time.Hour, -time.Minute, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expiresAt := now.Add(tt.left)
			assert.Equal(t, tt.want, needsRenewal(expiresAt.Add(-tt.lifetime), expiresAt))
		})
	}
	assert.True(t, needsRenewal(now, time.Time{}), "unknown expiry is always renewed")
	assert.False(t, jwtNeedsRenewal(&DelegationJWT{}), "a JWT without exp is never renewed")
}

func TestTokenSource_ReusesCachedSubjectTokenWithoutRefreshToken(t *testing.T) {
	newRaw := buildDelegationJWT(t, "user@example.com", "mcp-server", time.Now().Add(15*time.Minute).Unix())
	var gotSubject, gotActor string
	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		gotSubject, gotActor = r.PostForm.Get("subject_token"), r.PostForm.Get("actor_token")
		fmt.Fprintf(w, `{"access_token":%q}`, newRaw)
	}))
	t.Cleanup(sts.Close)
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"access_token":"fresh-actor"}`)
	}))
	t.Cleanup(idp.Close)

	ts := NewTokenSource(AuthConfig{STSEndpoint: sts.URL, TokenURL: idp.URL, ActorClientID: "a", ActorClientSecret: "s"},
		initialJWT(t, time.Now().Add(time.Minute)), &PKCEResult{SubjectToken: "cached-subject"})

	_, err := ts.Token(context.Background())
	require.NoError(t, err)

	assert.Equal(t, newRaw, ts.Get().Raw)
	assert.Equal(t, "cached-subject", gotSubject)
	assert.Equal(t, "fresh-actor", gotActor)
}

// revokeCall is one request received by the fake revocation endpoint.
type revokeCall struct {
	token, hint, clientID, clientSecret string
	basic                               bool
}

// newRevokeRecorder starts a fake RFC 7009 endpoint that records every request.
// Tokens listed in failTokens get HTTP 500.
func newRevokeRecorder(t *testing.T, failTokens ...string) (url string, calls func() []revokeCall) {
	t.Helper()
	var mu sync.Mutex
	var recorded []revokeCall
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		id, secret, basic := r.BasicAuth()
		if !basic {
			id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
		}
		c := revokeCall{r.PostForm.Get("token"), r.PostForm.Get("token_type_hint"), id, secret, basic}
		mu.Lock()
		recorded = append(recorded, c)
		mu.Unlock()
		if slices.Contains(failTokens, c.token) {
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL, func() []revokeCall {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(recorded)
	}
}

func revokedTokens(calls []revokeCall) []string {
	tokens := make([]string, 0, len(calls))
	for _, c := range calls {
		tokens = append(tokens, c.token)
	}
	return tokens
}

func revokeConfig(revokeURL string) AuthConfig {
	return AuthConfig{
		RevokeURL:           revokeURL,
		SubjectClientID:     "subject-app",
		SubjectClientSecret: "subject-secret",
		ActorClientID:       "actor-app",
		ActorClientSecret:   "actor-secret",
	}
}

// With a refresh token, only it and the Actor access token are revoked. The
// Subject (confidential) authenticates with client_secret_basic and the Actor
// with client_secret_post.
func TestTokenSource_Revoke(t *testing.T) {
	url, calls := newRevokeRecorder(t)
	ts := NewTokenSource(revokeConfig(url), initialJWT(t, time.Now().Add(time.Hour)),
		&PKCEResult{SubjectToken: "subject-at", SubjectRefreshToken: "subject-rt", ActorToken: "actor-at"})

	ts.Revoke()

	byToken := map[string]revokeCall{}
	for _, c := range calls() {
		byToken[c.token] = c
	}
	require.Len(t, byToken, 2, "the subject access token is not revoked when its refresh token is")
	assert.Equal(t, revokeCall{"subject-rt", "refresh_token", "subject-app", "subject-secret", true}, byToken["subject-rt"])
	assert.Equal(t, revokeCall{"actor-at", "access_token", "actor-app", "actor-secret", false}, byToken["actor-at"])
}

func TestTokenSource_Revoke_NoRefreshTokenRevokesSubjectAccessToken(t *testing.T) {
	url, calls := newRevokeRecorder(t)
	ts := NewTokenSource(revokeConfig(url), initialJWT(t, time.Now().Add(time.Hour)),
		&PKCEResult{SubjectToken: "subject-at", ActorToken: "actor-at"})

	ts.Revoke()

	assert.ElementsMatch(t, []string{"subject-at", "actor-at"}, revokedTokens(calls()))
}

// A failed refresh token revocation falls back to the Subject access token. Each
// outcome is logged by token name and reason, never with a token value.
func TestTokenSource_Revoke_RefreshFailureFallsBackToAccessToken(t *testing.T) {
	url, calls := newRevokeRecorder(t, "subject-rt")
	logger, hook := test.NewNullLogger()
	ts := NewTokenSource(revokeConfig(url), initialJWT(t, time.Now().Add(time.Hour)),
		&PKCEResult{SubjectToken: "subject-at", SubjectRefreshToken: "subject-rt", ActorToken: "actor-at"}).WithLogger(logger)

	ts.Revoke()

	assert.ElementsMatch(t, []string{"subject-rt", "subject-at", "actor-at"}, revokedTokens(calls()))
	byToken := map[string]*log.Entry{}
	for _, e := range hook.AllEntries() {
		byToken[e.Data["token"].(string)] = e
		for _, secret := range []string{"subject-rt", "subject-at", "actor-at"} {
			assert.NotContains(t, fmt.Sprint(e.Message, e.Data), secret)
		}
	}
	require.Len(t, byToken, 3)
	refresh := byToken["subject_refresh_token"]
	assert.Equal(t, "failed", refresh.Data["outcome"])
	assert.Equal(t, "revoke endpoint returned HTTP 500", refresh.Data["reason"])
	assert.Equal(t, log.WarnLevel, refresh.Level)
	assert.Equal(t, "revoked", byToken["subject_access_token"].Data["outcome"])
	assert.Equal(t, "revoked", byToken["actor_access_token"].Data["outcome"])
}

// revokeOutcomes lists "token:outcome" for each revocation that was logged.
func revokeOutcomes(hook *test.Hook) []string {
	var out []string
	for _, e := range hook.AllEntries() {
		out = append(out, fmt.Sprintf("%v:%v", e.Data["token"], e.Data["outcome"]))
	}
	return out
}

func TestTokenSource_Revoke_Skipped(t *testing.T) {
	t.Run("revocation URL not configured", func(t *testing.T) {
		logger, hook := test.NewNullLogger()
		ts := NewTokenSource(revokeConfig(""), initialJWT(t, time.Now().Add(time.Hour)),
			&PKCEResult{SubjectRefreshToken: "subject-rt", ActorToken: "actor-at"}).WithLogger(logger)

		ts.Revoke()

		assert.ElementsMatch(t, []string{"subject_refresh_token:skipped", "actor_access_token:skipped"}, revokeOutcomes(hook))
		assert.Equal(t, "revocation URL not configured", hook.AllEntries()[0].Data["reason"])
	})

	t.Run("no tokens held", func(t *testing.T) {
		url, calls := newRevokeRecorder(t)
		logger, hook := test.NewNullLogger()
		ts := NewTokenSource(revokeConfig(url), initialJWT(t, time.Now().Add(time.Hour)), &PKCEResult{}).WithLogger(logger)

		ts.Revoke()

		assert.ElementsMatch(t, []string{"subject_access_token:skipped", "actor_access_token:skipped"}, revokeOutcomes(hook))
		assert.Empty(t, calls())
	})
}

// Revoke waits for a renewal in flight, so the refresh token that renewal
// rotated to is the one revoked, not the one it replaced.
func TestTokenSource_Revoke_WaitsForRenewalInFlight(t *testing.T) {
	f := newRefreshFixture(t, buildDelegationJWT(t, "user@example.com", "mcp-server", time.Now().Add(time.Hour).Unix()))
	f.stsDelay = 300 * time.Millisecond
	url, calls := newRevokeRecorder(t)
	f.cfg.RevokeURL = url
	issuedAt, expiresAt := nearExpiry()
	now := time.Now()
	ts := NewTokenSource(f.cfg, initialJWT(t, now.Add(time.Minute)), &PKCEResult{
		SubjectToken: "old-subject", SubjectRefreshToken: "old-rt", SubjectIssuedAt: issuedAt, SubjectExpiresAt: expiresAt,
		ActorToken: "actor-access", ActorIssuedAt: now.Add(-time.Minute), ActorExpiresAt: now.Add(time.Hour),
	})

	renewed := make(chan error, 1)
	go func() {
		_, err := ts.Token(context.Background())
		renewed <- err
	}()
	// The IdP has rotated the refresh token and the slow STS exchange is running.
	require.Eventually(t, func() bool { return f.idpCalls.Load() == 1 }, 5*time.Second, 5*time.Millisecond)

	ts.Revoke()

	require.NoError(t, <-renewed)
	assert.ElementsMatch(t, []string{"rotated-1", "actor-access"}, revokedTokens(calls()))
}

// Each revocation request is bounded by revokeTimeout. A hung endpoint is
// logged as failed, and with the Subject fallback the Subject side makes two
// sequential requests, so Revoke returns in about twice the timeout.
func TestTokenSource_Revoke_Timeout(t *testing.T) {
	old := revokeTimeout
	revokeTimeout = 50 * time.Millisecond
	t.Cleanup(func() { revokeTimeout = old })
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release) })
	logger, hook := test.NewNullLogger()
	ts := NewTokenSource(revokeConfig(srv.URL), initialJWT(t, time.Now().Add(time.Hour)),
		&PKCEResult{SubjectToken: "subject-at", SubjectRefreshToken: "subject-rt", ActorToken: "actor-at"}).WithLogger(logger)

	start := time.Now()
	ts.Revoke()

	assert.Less(t, time.Since(start), time.Second)
	assert.ElementsMatch(t,
		[]string{"subject_refresh_token:failed", "subject_access_token:failed", "actor_access_token:failed"},
		revokeOutcomes(hook))
}
