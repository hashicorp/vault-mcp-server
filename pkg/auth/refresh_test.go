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

// refreshFixture wires a fake IdP token endpoint (refresh_token grant) and a fake
// STS endpoint that returns newJWT.
type refreshFixture struct {
	cfg        AuthConfig
	idpCalls   atomic.Int32
	stsCalls   atomic.Int32
	idpStatus  int
	refreshIDs []string
}

func newRefreshFixture(t *testing.T, newJWT string) *refreshFixture {
	t.Helper()
	f := &refreshFixture{idpStatus: http.StatusOK}

	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		assert.Equal(t, "refresh_token", r.PostForm.Get("grant_type"))
		n := f.idpCalls.Add(1)
		f.refreshIDs = append(f.refreshIDs, r.PostForm.Get("refresh_token"))
		if f.idpStatus != http.StatusOK {
			http.Error(w, `{"error":"invalid_grant"}`, f.idpStatus)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":"access-%d","refresh_token":"rotated-%d"}`, n, n)
	}))
	t.Cleanup(idp.Close)

	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		assert.Equal(t, "access-1", r.PostForm.Get("subject_token"))
		assert.Equal(t, "access-2", r.PostForm.Get("actor_token"))
		f.stsCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":%q}`, newJWT)
	}))
	t.Cleanup(sts.Close)

	f.cfg = AuthConfig{
		Enabled:     true,
		ClientID:    "client",
		TokenURL:    idp.URL,
		STSEndpoint: sts.URL,
	}
	return f
}

func initialJWT(t *testing.T, exp time.Time) *DelegationJWT {
	t.Helper()
	jwt, err := ParseUnsigned(buildDelegationJWT(t, "user@example.com", "mcp-server", exp.Unix()))
	require.NoError(t, err)
	return jwt
}

func TestTokenSource_RefreshesWithinWindow(t *testing.T) {
	newRaw := buildDelegationJWT(t, "user@example.com", "mcp-server", time.Now().Add(15*time.Minute).Unix())
	f := newRefreshFixture(t, newRaw)

	ts := NewTokenSource(f.cfg, initialJWT(t, time.Now().Add(time.Minute)),
		&PKCEResult{SubjectRefreshToken: "subject-rt", ActorRefreshToken: "actor-rt"})
	var notified atomic.Pointer[DelegationJWT]
	ts.OnRefresh(func(j *DelegationJWT) { notified.Store(j) })

	require.NoError(t, ts.refreshIfNeeded(context.Background()))

	assert.Equal(t, newRaw, ts.Get().Raw)
	assert.Equal(t, newRaw, notified.Load().Raw)
	assert.Equal(t, []string{"subject-rt", "actor-rt"}, f.refreshIDs)
	assert.EqualValues(t, 1, f.stsCalls.Load())
	// Rotated refresh tokens replace the originals.
	assert.Equal(t, "rotated-1", ts.subjectRefreshToken)
	assert.Equal(t, "rotated-2", ts.actorRefreshToken)
}

func TestTokenSource_RefreshesAlreadyExpiredJWT(t *testing.T) {
	newRaw := buildDelegationJWT(t, "user@example.com", "mcp-server", time.Now().Add(15*time.Minute).Unix())
	f := newRefreshFixture(t, newRaw)

	// ParseUnsigned rejects expired tokens, so build the expired JWT directly.
	expired := &DelegationJWT{Sub: "user@example.com", Exp: time.Now().Add(-10 * time.Hour), Raw: "old"}
	ts := NewTokenSource(f.cfg, expired, &PKCEResult{SubjectRefreshToken: "s", ActorRefreshToken: "a"})

	require.NoError(t, ts.refreshIfNeeded(context.Background()))
	assert.Equal(t, newRaw, ts.Get().Raw)
}

func TestTokenSource_SkipsWhenFarFromExpiry(t *testing.T) {
	f := newRefreshFixture(t, "unused")
	jwt := initialJWT(t, time.Now().Add(time.Hour))
	ts := NewTokenSource(f.cfg, jwt, &PKCEResult{SubjectRefreshToken: "s", ActorRefreshToken: "a"})

	require.NoError(t, ts.refreshIfNeeded(context.Background()))

	assert.Same(t, jwt, ts.Get())
	assert.EqualValues(t, 0, f.idpCalls.Load())
	assert.EqualValues(t, 0, f.stsCalls.Load())
}

func TestTokenSource_RefreshFailureKeepsCurrentJWT(t *testing.T) {
	f := newRefreshFixture(t, "unused")
	f.idpStatus = http.StatusBadRequest
	jwt := initialJWT(t, time.Now().Add(time.Minute))
	ts := NewTokenSource(f.cfg, jwt, &PKCEResult{SubjectRefreshToken: "s", ActorRefreshToken: "a"})

	err := ts.refreshIfNeeded(context.Background())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "Subject")
	assert.Same(t, jwt, ts.Get())
	assert.EqualValues(t, 0, f.stsCalls.Load())
}

func TestTokenSource_NilAndNoRefreshTokens(t *testing.T) {
	var nilSource *TokenSource
	assert.Nil(t, nilSource.Get())
	nilSource.Start(context.Background()) // must not panic

	ts := NewTokenSource(AuthConfig{}, initialJWT(t, time.Now().Add(time.Hour)), &PKCEResult{})
	assert.False(t, ts.HasRefreshTokens())
	ts.Start(context.Background()) // logs a warning, starts no goroutine
}

func TestTokenSource_StartRefreshesInBackground(t *testing.T) {
	newRaw := buildDelegationJWT(t, "user@example.com", "mcp-server", time.Now().Add(15*time.Minute).Unix())
	f := newRefreshFixture(t, newRaw)

	ts := NewTokenSource(f.cfg, initialJWT(t, time.Now().Add(time.Minute)),
		&PKCEResult{SubjectToken: "st", ActorToken: "at", SubjectRefreshToken: "s", ActorRefreshToken: "a"})
	ts.interval = 10 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ts.Start(ctx)

	require.Eventually(t, func() bool { return ts.Get().Raw == newRaw }, 2*time.Second, 10*time.Millisecond)
}

func TestTokenSource_ReusesCachedTokensWithoutRefreshTokens(t *testing.T) {
	newRaw := buildDelegationJWT(t, "user@example.com", "mcp-server", time.Now().Add(15*time.Minute).Unix())
	var gotSubject, gotActor string
	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		gotSubject, gotActor = r.PostForm.Get("subject_token"), r.PostForm.Get("actor_token")
		fmt.Fprintf(w, `{"access_token":%q}`, newRaw)
	}))
	t.Cleanup(sts.Close)

	ts := NewTokenSource(AuthConfig{STSEndpoint: sts.URL}, initialJWT(t, time.Now().Add(time.Minute)),
		&PKCEResult{SubjectToken: "cached-subject", ActorToken: "cached-actor"})

	require.NoError(t, ts.refreshIfNeeded(context.Background()))

	assert.Equal(t, newRaw, ts.Get().Raw)
	assert.Equal(t, "cached-subject", gotSubject)
	assert.Equal(t, "cached-actor", gotActor)
}

func TestAcquireTokenSource_CapturesRefreshTokens(t *testing.T) {
	raw := buildDelegationJWT(t, "user@example.com", "mcp-server", time.Now().Add(15*time.Minute).Unix())
	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `{"access_token":%q}`, raw)
	}))
	t.Cleanup(sts.Close)

	runner := func(context.Context, PKCEConfig) (*PKCEResult, error) {
		return &PKCEResult{SubjectToken: "s", ActorToken: "a", SubjectRefreshToken: "srt", ActorRefreshToken: "art"}, nil
	}
	ts, err := AcquireTokenSource(context.Background(), AuthConfig{Enabled: true, STSEndpoint: sts.URL}, runner)

	require.NoError(t, err)
	require.NotNil(t, ts)
	assert.Equal(t, raw, ts.Get().Raw)
	assert.True(t, ts.HasRefreshTokens())

	disabled, err := AcquireTokenSource(context.Background(), AuthConfig{}, nil)
	require.NoError(t, err)
	assert.Nil(t, disabled)
}
