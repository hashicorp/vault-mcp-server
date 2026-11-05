// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package auth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault-mcp-server/pkg/auth"
	"github.com/mark3labs/mcp-go/mcp"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var urlPattern = regexp.MustCompile(`https?://\S+`)

func testJWT(t *testing.T) string {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"sub": "user@example.com",
		"act": map[string]string{"sub": "mcp-server"},
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(15 * time.Minute).Unix(),
	})
	require.NoError(t, err)
	enc := base64.RawURLEncoding
	return enc.EncodeToString([]byte(`{"alg":"none"}`)) + "." + enc.EncodeToString(payload) + ".sig"
}

func newLoginFixture(t *testing.T, actorPassword bool) (*LoginState, *int) {
	t.Helper()

	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"access_token":"at","refresh_token":"rt"}`)
	}))
	t.Cleanup(idp.Close)

	jwt := testJWT(t)
	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `{"access_token":%q}`, jwt)
	}))
	t.Cleanup(sts.Close)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port
	require.NoError(t, ln.Close())

	cfg := auth.AuthConfig{
		Enabled:         true,
		SubjectClientID: "subject-app",
		ActorClientID:   "actor-app",
		AuthURL:         "https://idp.example/authorize",
		TokenURL:        idp.URL,
		RedirectURL:     fmt.Sprintf("http://127.0.0.1:%d/callback", port),
		STSEndpoint:     sts.URL,
		Deadline:        time.Minute,
	}
	if actorPassword {
		cfg.ActorUsername, cfg.ActorPassword = "agent", "secret"
	}

	ready := new(int)
	logger := log.New()
	logger.SetLevel(log.PanicLevel)
	s := &LoginState{cfg: cfg, logger: logger, onReady: func(*auth.TokenSource) { *ready++ }}
	t.Cleanup(s.Close)
	return s, ready
}

// signIn plays the browser: it follows the sign-in URL found in text back to
// the local callback with an authorization code (or an IdP error).
func signIn(t *testing.T, text, idpError string) {
	t.Helper()
	authURL, err := url.Parse(urlPattern.FindString(text))
	require.NoError(t, err)
	q := authURL.Query()
	cb := url.Values{"state": {q.Get("state")}}
	if idpError != "" {
		cb.Set("error", idpError)
	} else {
		cb.Set("code", "code")
	}
	resp, err := http.Get(q.Get("redirect_uri") + "?" + cb.Encode()) //nolint:noctx // test helper
	require.NoError(t, err)
	resp.Body.Close()
}

func loginText(t *testing.T, s *LoginState) string {
	t.Helper()
	res, err := s.login()
	require.NoError(t, err)
	return res.Content[0].(mcp.TextContent).Text
}

func waitStatus(t *testing.T, s *LoginState, substr string) {
	t.Helper()
	require.Eventually(t, func() bool { return strings.Contains(s.status(), substr) }, 5*time.Second, 10*time.Millisecond, "status: %s", s.status())
}

func TestLogin_BrowserActorFlow(t *testing.T) {
	s, ready := newLoginFixture(t, false)

	assert.Contains(t, s.status(), "Not authenticated")

	first := loginText(t, s)
	assert.Contains(t, first, "human user")
	assert.Equal(t, urlPattern.FindString(first), urlPattern.FindString(loginText(t, s)), "mid-flow login returns the same URL")

	signIn(t, first, "")
	waitStatus(t, s, "sign in as the agent")

	actor := loginText(t, s)
	assert.Contains(t, actor, "agent")
	assert.NotEqual(t, urlPattern.FindString(first), urlPattern.FindString(actor))

	signIn(t, actor, "")
	waitStatus(t, s, "Authenticated. sub=user@example.com")
	assert.Equal(t, 1, *ready)
	assert.Contains(t, loginText(t, s), "Already authenticated")
}

func TestLogin_ActorPasswordFlow(t *testing.T) {
	s, ready := newLoginFixture(t, true)

	text := loginText(t, s)
	assert.Contains(t, text, "agent is signed in automatically")

	signIn(t, text, "")
	waitStatus(t, s, "Authenticated. sub=user@example.com")
	assert.Equal(t, 1, *ready)
}

func TestLogin_FailureReturnsToLoggedOut(t *testing.T) {
	s, ready := newLoginFixture(t, false)

	signIn(t, loginText(t, s), "access_denied")
	waitStatus(t, s, "last sign-in failed: human sign-in failed")
	assert.Zero(t, *ready)

	// A new attempt is possible after a failure.
	assert.Contains(t, loginText(t, s), "human user")
	assert.NotContains(t, s.status(), "failed")
}
