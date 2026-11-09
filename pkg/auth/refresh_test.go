// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package auth

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

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
			fmt.Fprint(w, `{"access_token":"actor-access"}`)
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
		fmt.Fprintf(w, `{"access_token":"subject-access","refresh_token":"rotated-%d"}`, n)
	}))
	t.Cleanup(idp.Close)

	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		assert.Equal(t, "subject-access", r.PostForm.Get("subject_token"))
		assert.Equal(t, "actor-access", r.PostForm.Get("actor_token"))
		f.stsCalls.Add(1)
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

func initialJWT(t *testing.T, exp time.Time) *DelegationJWT {
	t.Helper()
	jwt, err := ParseUnsigned(buildDelegationJWT(t, "user@example.com", "mcp-server", exp.Unix()))
	require.NoError(t, err)
	// Test JWTs carry no iat claim; model a 2h lifetime so the 10% refresh window is 12m.
	jwt.Iat = exp.Add(-2 * time.Hour)
	return jwt
}

func TestTokenSource_Close(t *testing.T) {
	f := newRefreshFixture(t, "unused")
	ts := NewTokenSource(f.cfg, initialJWT(t, time.Now().Add(time.Minute)),
		&PKCEResult{SubjectToken: "subject", SubjectRefreshToken: "srt"})
	ts.Start(context.Background())
	ts.Close()
	ts.Close()
	assert.Nil(t, ts.Get())
	assert.False(t, ts.HasRefreshToken())
	assert.Empty(t, ts.subjectToken)
	assert.Empty(t, ts.subjectRefreshToken)
	require.NoError(t, ts.refreshIfNeeded(context.Background()))
	assert.Zero(t, f.idpCalls.Load())
	assert.Zero(t, f.actorCalls.Load())
	ts.Start(context.Background())
	assert.Nil(t, ts.cancel)
}

func TestTokenSource_RefreshesWithinWindow(t *testing.T) {
	newRaw := buildDelegationJWT(t, "user@example.com", "mcp-server", time.Now().Add(15*time.Minute).Unix())
	f := newRefreshFixture(t, newRaw)

	ts := NewTokenSource(f.cfg, initialJWT(t, time.Now().Add(time.Minute)),
		&PKCEResult{SubjectRefreshToken: "subject-rt"})
	var notified atomic.Pointer[DelegationJWT]
	ts.OnRefresh(func(j *DelegationJWT) { notified.Store(j) })

	require.NoError(t, ts.refreshIfNeeded(context.Background()))

	assert.Equal(t, newRaw, ts.Get().Raw)
	assert.Equal(t, newRaw, notified.Load().Raw)
	assert.Equal(t, []string{"subject-rt"}, f.refreshIDs)
	assert.Equal(t, []string{"subject-app", "actor-app"}, f.clientIDs)
	assert.EqualValues(t, 1, f.actorCalls.Load())
	assert.EqualValues(t, 1, f.stsCalls.Load())
	// The rotated refresh token replaces the original.
	assert.Equal(t, "rotated-1", ts.subjectRefreshToken)
}

func TestTokenSource_RefreshesWithSeparateApplications(t *testing.T) {
	f := newRefreshFixture(t, buildDelegationJWT(t, "user", "actor", time.Now().Add(time.Hour).Unix()))
	f.cfg.SubjectClientID, f.cfg.SubjectClientSecret = "subject-app", "subject-secret"
	f.cfg.ActorClientID, f.cfg.ActorClientSecret = "actor-app", "actor-secret"
	ts := NewTokenSource(f.cfg, initialJWT(t, time.Now().Add(time.Minute)),
		&PKCEResult{SubjectRefreshToken: "subject-rt"})

	require.NoError(t, ts.refreshIfNeeded(context.Background()))
	assert.Equal(t, []string{"subject-app", "actor-app"}, f.clientIDs)
	assert.Equal(t, []string{"subject-secret", "actor-secret"}, f.secrets)
	assert.Equal(t, []string{"subject-rt"}, f.refreshIDs)
}

func TestTokenSource_RefreshesAlreadyExpiredJWT(t *testing.T) {
	newRaw := buildDelegationJWT(t, "user@example.com", "mcp-server", time.Now().Add(15*time.Minute).Unix())
	f := newRefreshFixture(t, newRaw)

	// ParseUnsigned rejects expired tokens, so build the expired JWT directly.
	expired := &DelegationJWT{Sub: "user@example.com", Exp: time.Now().Add(-10 * time.Hour), Raw: "old"}
	ts := NewTokenSource(f.cfg, expired, &PKCEResult{SubjectRefreshToken: "s"})

	require.NoError(t, ts.refreshIfNeeded(context.Background()))
	assert.Equal(t, newRaw, ts.Get().Raw)
}

func TestTokenSource_SkipsWhenFarFromExpiry(t *testing.T) {
	f := newRefreshFixture(t, "unused")
	jwt := initialJWT(t, time.Now().Add(time.Hour))
	ts := NewTokenSource(f.cfg, jwt, &PKCEResult{SubjectRefreshToken: "s"})

	require.NoError(t, ts.refreshIfNeeded(context.Background()))

	assert.Same(t, jwt, ts.Get())
	assert.EqualValues(t, 0, f.idpCalls.Load())
	assert.EqualValues(t, 0, f.actorCalls.Load())
	assert.EqualValues(t, 0, f.stsCalls.Load())
}

func TestTokenSource_RefreshFailureKeepsCurrentJWT(t *testing.T) {
	f := newRefreshFixture(t, "unused")
	f.idpStatus = http.StatusServiceUnavailable
	jwt := initialJWT(t, time.Now().Add(time.Minute))
	ts := NewTokenSource(f.cfg, jwt, &PKCEResult{SubjectRefreshToken: "s"})

	err := ts.refreshIfNeeded(context.Background())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "Subject")
	assert.Same(t, jwt, ts.Get())
	assert.EqualValues(t, 0, f.stsCalls.Load())
}

func TestTokenSource_InvalidGrantRequiresReauthentication(t *testing.T) {
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"error":"invalid_grant"}`)
	}))
	t.Cleanup(idp.Close)
	ts := NewTokenSource(AuthConfig{TokenURL: idp.URL}, initialJWT(t, time.Now().Add(time.Minute)),
		&PKCEResult{SubjectToken: "subject", SubjectRefreshToken: "subject-rt"})
	invalidated := false
	ts.OnInvalidated(func() { invalidated = true })
	require.ErrorContains(t, ts.refreshIfNeeded(context.Background()), "re-authentication required")
	assert.True(t, invalidated)
	assert.Nil(t, ts.Get())
	assert.False(t, ts.HasRefreshToken())
	assert.Empty(t, ts.subjectToken)
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

	err := ts.refreshIfNeeded(context.Background())

	require.ErrorContains(t, err, "Actor")
	assert.False(t, invalidated)
	assert.Same(t, jwt, ts.Get())
	assert.EqualValues(t, 0, f.stsCalls.Load())
}

func TestTokenSource_NilAndNoRefreshTokens(t *testing.T) {
	var nilSource *TokenSource
	assert.Nil(t, nilSource.Get())
	nilSource.Start(context.Background()) // must not panic

	ts := NewTokenSource(AuthConfig{}, initialJWT(t, time.Now().Add(time.Hour)), &PKCEResult{})
	assert.False(t, ts.HasRefreshToken())
	ts.Start(context.Background()) // logs a warning, starts no goroutine
}

func TestTokenSource_StartRefreshesInBackground(t *testing.T) {
	newRaw := buildDelegationJWT(t, "user@example.com", "mcp-server", time.Now().Add(15*time.Minute).Unix())
	f := newRefreshFixture(t, newRaw)

	ts := NewTokenSource(f.cfg, initialJWT(t, time.Now().Add(time.Minute)),
		&PKCEResult{SubjectToken: "st", SubjectRefreshToken: "s"})
	ts.interval = 10 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ts.Start(ctx)

	require.Eventually(t, func() bool { return ts.Get().Raw == newRaw }, 2*time.Second, 10*time.Millisecond)
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

	require.NoError(t, ts.refreshIfNeeded(context.Background()))

	assert.Equal(t, newRaw, ts.Get().Raw)
	assert.Equal(t, "cached-subject", gotSubject)
	assert.Equal(t, "fresh-actor", gotActor)
}

// TestTokenSource_Revoke: the Subject (confidential) authenticates with
// client_secret_basic and the Actor with client_secret_post.
func TestTokenSource_Revoke(t *testing.T) {
	type call struct {
		basicID, basicSecret string
		hasBasic             bool
		form                 map[string]string
	}
	calls := make(chan call, 2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		id, secret, ok := r.BasicAuth()
		calls <- call{id, secret, ok, map[string]string{
			"token":           r.PostForm.Get("token"),
			"token_type_hint": r.PostForm.Get("token_type_hint"),
			"client_id":       r.PostForm.Get("client_id"),
			"client_secret":   r.PostForm.Get("client_secret"),
		}}
	}))
	t.Cleanup(srv.Close)

	f := newRefreshFixture(t, "unused")
	f.cfg.RevokeURL = srv.URL
	f.cfg.SubjectClientID, f.cfg.SubjectClientSecret = "subject-app", "subject-secret"
	f.cfg.ActorClientID, f.cfg.ActorClientSecret = "actor-app", "actor-secret"
	ts := NewTokenSource(f.cfg, initialJWT(t, time.Now().Add(time.Hour)),
		&PKCEResult{SubjectRefreshToken: "subject-rt", ActorToken: "actor-at"})

	require.NoError(t, ts.Revoke())
	close(calls)

	byToken := map[string]call{}
	for c := range calls {
		byToken[c.form["token"]] = c
	}
	require.Len(t, byToken, 2)

	subject := byToken["subject-rt"]
	assert.True(t, subject.hasBasic)
	assert.Equal(t, "subject-app", subject.basicID)
	assert.Equal(t, "subject-secret", subject.basicSecret)
	assert.Equal(t, "refresh_token", subject.form["token_type_hint"])
	assert.Empty(t, subject.form["client_secret"])

	actor := byToken["actor-at"]
	assert.False(t, actor.hasBasic)
	assert.Equal(t, "actor-app", actor.form["client_id"])
	assert.Equal(t, "actor-secret", actor.form["client_secret"])
	assert.Equal(t, "access_token", actor.form["token_type_hint"])
}
