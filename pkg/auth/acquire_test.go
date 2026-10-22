// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakePKCERunner returns a PKCERunner that immediately returns the given tokens
// without opening a browser or binding a port.
func fakePKCERunner(subjectToken, actorToken string, err error) PKCERunner {
	return func(_ context.Context, _, _ PKCEConfig) (*PKCEResult, error) {
		if err != nil {
			return nil, err
		}
		return &PKCEResult{SubjectToken: subjectToken, ActorToken: actorToken}, nil
	}
}

func TestAuthConfig_ApplicationCredentials(t *testing.T) {
	for _, tc := range []struct {
		name                             string
		subjectID, subjectSecret         string
		actorID, actorSecret             string
		wantSubjectID, wantSubjectSecret string
		wantActorID, wantActorSecret     string
	}{
		{name: "unset"},
		{name: "separate", subjectID: "subject", subjectSecret: "subject-secret", actorID: "actor", actorSecret: "actor-secret", wantSubjectID: "subject", wantSubjectSecret: "subject-secret", wantActorID: "actor", wantActorSecret: "actor-secret"},
		{name: "subject-only", subjectID: "subject", subjectSecret: "subject-secret", wantSubjectID: "subject", wantSubjectSecret: "subject-secret"},
		{name: "actor-only", actorID: "actor", actorSecret: "actor-secret", wantActorID: "actor", wantActorSecret: "actor-secret"},
		{name: "public", subjectID: "subject", actorID: "actor", wantSubjectID: "subject", wantActorID: "actor"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := AuthConfig{
				SubjectClientID: tc.subjectID, SubjectClientSecret: tc.subjectSecret,
				ActorClientID: tc.actorID, ActorClientSecret: tc.actorSecret,
				AuthURL: "https://idp/auth", TokenURL: "https://idp/token",
				RedirectURL: "http://localhost/callback", Scopes: []string{"openid"}, Deadline: time.Minute,
			}
			subject, actor := cfg.SubjectPKCEConfig(), cfg.ActorPKCEConfig()
			assert.Equal(t, tc.wantSubjectID, subject.ClientID)
			assert.Equal(t, tc.wantSubjectSecret, subject.ClientSecret)
			assert.Equal(t, tc.wantActorID, actor.ClientID)
			assert.Equal(t, tc.wantActorSecret, actor.ClientSecret)
			for _, flow := range []PKCEConfig{subject, actor} {
				assert.Equal(t, cfg.AuthURL, flow.AuthURL)
				assert.Equal(t, cfg.TokenURL, flow.TokenURL)
				assert.Equal(t, cfg.RedirectURL, flow.RedirectURL)
				assert.Equal(t, cfg.Scopes, flow.Scopes)
				assert.Equal(t, cfg.Deadline, flow.Deadline)
			}
		})
	}
}

func TestAcquireTokens_SeparateApplications(t *testing.T) {
	sentinel := errors.New("stop before browser")
	runner := func(_ context.Context, subjectCfg, actorCfg PKCEConfig) (*PKCEResult, error) {
		assert.Equal(t, "subject", subjectCfg.ClientID)
		assert.Equal(t, "subject-secret", subjectCfg.ClientSecret)
		assert.Equal(t, "actor", actorCfg.ClientID)
		assert.Equal(t, "actor-secret", actorCfg.ClientSecret)
		return nil, sentinel
	}
	_, err := AcquireTokens(context.Background(), AuthConfig{
		Enabled: true, SubjectClientID: "subject", SubjectClientSecret: "subject-secret",
		ActorClientID: "actor", ActorClientSecret: "actor-secret",
	}, runner)
	require.ErrorIs(t, err, sentinel)
}

// TestAcquireTokens_Disabled: VAULT_MCP_AUTH_ENABLED=false → (nil, nil), no browser opened.
func TestAcquireTokens_Disabled(t *testing.T) {
	cfg := AuthConfig{Enabled: false}
	// pkceRunner must not be called; passing nil verifies it is never invoked.
	jwt, err := AcquireTokens(context.Background(), cfg, nil)
	assert.Nil(t, jwt)
	assert.NoError(t, err)
}

// TestAcquireTokens_ValidConfig: auth enabled → PKCE runs → STS called → DelegationJWT returned.
func TestAcquireTokens_ValidConfig(t *testing.T) {
	futureExp := time.Now().Add(1 * time.Hour).Unix()
	jwtStr := buildDelegationJWT(t, "user@example.com", "mcp-server", futureExp)

	// Fake STS endpoint returns the delegation JWT.
	stsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":%q}`, jwtStr)
	}))
	t.Cleanup(stsSrv.Close)

	cfg := AuthConfig{
		Enabled:         true,
		SubjectClientID: "subject-client",
		ActorClientID:   "actor-client",
		AuthURL:         "https://idp.example.com/auth",
		TokenURL:        "https://idp.example.com/token",
		RedirectURL:     "http://localhost:9000/callback",
		STSEndpoint:     stsSrv.URL,
	}

	runner := fakePKCERunner("subject-tok", "actor-tok", nil)
	jwt, err := AcquireTokens(context.Background(), cfg, runner)

	require.NoError(t, err)
	require.NotNil(t, jwt)
	assert.Equal(t, "user@example.com", jwt.Sub)
	assert.Equal(t, "mcp-server", jwt.Act.Sub)
	assert.Equal(t, jwtStr, jwt.Raw)
}

// TestAcquireTokens_PKCEError: PKCE runner returns an error → AcquireTokens returns that error.
func TestAcquireTokens_PKCEError(t *testing.T) {
	cfg := AuthConfig{
		Enabled:     true,
		STSEndpoint: "https://sts.example.com/exchange",
	}

	pkceErr := errors.New("browser closed by user")
	runner := fakePKCERunner("", "", pkceErr)

	jwt, err := AcquireTokens(context.Background(), cfg, runner)
	assert.Nil(t, jwt)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "browser closed by user")
}

// TestAcquireTokens_STSError: PKCE succeeds but STS returns non-2xx → error with HTTP status.
func TestAcquireTokens_STSError(t *testing.T) {
	stsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, `{"error":"unauthorized"}`)
	}))
	t.Cleanup(stsSrv.Close)

	cfg := AuthConfig{
		Enabled:     true,
		STSEndpoint: stsSrv.URL,
	}

	runner := fakePKCERunner("subject-tok", "actor-tok", nil)
	jwt, err := AcquireTokens(context.Background(), cfg, runner)
	assert.Nil(t, jwt)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "401")
}

// TestAcquireTokens_ExpiredJWT: STS returns an expired JWT → ErrTokenExpired propagated.
func TestAcquireTokens_ExpiredJWT(t *testing.T) {
	pastExp := time.Now().Add(-1 * time.Hour).Unix()
	jwtStr := buildDelegationJWT(t, "user@example.com", "mcp-server", pastExp)

	stsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":%q}`, jwtStr)
	}))
	t.Cleanup(stsSrv.Close)

	cfg := AuthConfig{
		Enabled:     true,
		STSEndpoint: stsSrv.URL,
	}

	runner := fakePKCERunner("subject-tok", "actor-tok", nil)
	jwt, err := AcquireTokens(context.Background(), cfg, runner)
	assert.Nil(t, jwt)
	assert.True(t, errors.Is(err, ErrTokenExpired),
		"expected ErrTokenExpired, got: %v", err)
}
