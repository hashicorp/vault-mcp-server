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

type loginFixture struct {
	state  *LoginState
	ready  int
	grants chan string
	// actorStatus lets a test make the IdP reject the actor client.
	actorStatus int
}

func newLoginFixture(t *testing.T) *loginFixture {
	t.Helper()
	f := &loginFixture{grants: make(chan string, 10), actorStatus: http.StatusOK}

	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		grant := r.PostForm.Get("grant_type")
		f.grants <- grant
		if grant == "client_credentials" {
			_, _, basic := r.BasicAuth()
			assert.False(t, basic)
			assert.Equal(t, "actor-app", r.PostForm.Get("client_id"))
			assert.Equal(t, "actor-secret", r.PostForm.Get("client_secret"))
			if f.actorStatus != http.StatusOK {
				http.Error(w, `{"error":"invalid_client"}`, f.actorStatus)
				return
			}
			fmt.Fprint(w, `{"access_token":"actor-at"}`)
			return
		}
		fmt.Fprint(w, `{"access_token":"subject-at","refresh_token":"rt"}`)
	}))
	t.Cleanup(idp.Close)

	jwt := testJWT(t)
	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		assert.Equal(t, "subject-at", r.PostForm.Get("subject_token"))
		assert.Equal(t, "actor-at", r.PostForm.Get("actor_token"))
		fmt.Fprintf(w, `{"access_token":%q}`, jwt)
	}))
	t.Cleanup(sts.Close)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port
	require.NoError(t, ln.Close())

	cfg := auth.AuthConfig{
		Enabled:           true,
		SubjectClientID:   "subject-app",
		ActorClientID:     "actor-app",
		ActorClientSecret: "actor-secret",
		AuthURL:           "https://idp.example/authorize",
		TokenURL:          idp.URL,
		RedirectURL:       fmt.Sprintf("http://127.0.0.1:%d/callback", port),
		STSEndpoint:       sts.URL,
		Deadline:          time.Minute,
	}

	logger := log.New()
	logger.SetLevel(log.PanicLevel)
	f.state = &LoginState{cfg: cfg, logger: logger, onReady: func(*auth.TokenSource) { f.ready++ }}
	t.Cleanup(f.state.Close)
	return f
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

func TestLogin_SubjectBrowserThenActorClientCredentials(t *testing.T) {
	f := newLoginFixture(t)
	s := f.state

	assert.Contains(t, s.status(), "Not authenticated")

	first := loginText(t, s)
	assert.Contains(t, first, "human user")
	assert.Equal(t, urlPattern.FindString(first), urlPattern.FindString(loginText(t, s)), "mid-flow login returns the same URL")

	signIn(t, first, "")
	waitStatus(t, s, "Authenticated. sub=user@example.com")
	assert.Equal(t, 1, f.ready)
	assert.Contains(t, loginText(t, s), "Already authenticated")

	// The subject uses the authorization code grant; the actor never opens a browser.
	assert.Equal(t, []string{"authorization_code", "client_credentials"}, []string{<-f.grants, <-f.grants})
}

func TestLogin_RequiresActorClientCredentials(t *testing.T) {
	for name, mutate := range map[string]func(*auth.AuthConfig){
		"no id":     func(c *auth.AuthConfig) { c.ActorClientID = "" },
		"no secret": func(c *auth.AuthConfig) { c.ActorClientSecret = "" },
	} {
		t.Run(name, func(t *testing.T) {
			f := newLoginFixture(t)
			mutate(&f.state.cfg)

			_, err := f.state.login()

			require.ErrorIs(t, err, auth.ErrActorCredentialsMissing)
			assert.Contains(t, f.state.status(), "Not authenticated")
		})
	}
}

func TestLogin_SubjectFailureReturnsToLoggedOut(t *testing.T) {
	f := newLoginFixture(t)
	s := f.state

	signIn(t, loginText(t, s), "access_denied")
	waitStatus(t, s, "last sign-in failed: human sign-in failed")
	assert.Zero(t, f.ready)

	// A new attempt is possible after a failure.
	assert.Contains(t, loginText(t, s), "human user")
	assert.NotContains(t, s.status(), "failed")
}

func TestLogin_ActorFailureReturnsToLoggedOut(t *testing.T) {
	f := newLoginFixture(t)
	f.actorStatus = http.StatusUnauthorized
	s := f.state

	signIn(t, loginText(t, s), "")
	waitStatus(t, s, "last sign-in failed: agent sign-in failed")
	assert.Zero(t, f.ready)
}
