// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/vault-mcp-server/pkg/auth"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
)

// TestSessionCleanup_RevokesAtIdP: ending a session revokes the Subject refresh
// token and the Actor access token at the IdP, logs each outcome, and discards
// the credentials.
func TestSessionCleanup_RevokesAtIdP(t *testing.T) {
	var mu sync.Mutex
	var revoked []string
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		mu.Lock()
		revoked = append(revoked, r.PostForm.Get("token"))
		mu.Unlock()
	}))
	t.Cleanup(idp.Close)

	logger, hook := test.NewNullLogger()
	ts := auth.NewTokenSource(auth.AuthConfig{RevokeURL: idp.URL},
		&auth.DelegationJWT{Sub: "user", Exp: time.Now().Add(time.Hour), Iat: time.Now(), Raw: "the-jwt"},
		&auth.PKCEResult{SubjectToken: "s-at", SubjectRefreshToken: "s-rt", ActorToken: "a-at"}).WithLogger(logger)
	activeTokenSource.Store(ts)

	closed := false
	sessionCleanup(func() { closed = true }, logger)()

	mu.Lock()
	slices.Sort(revoked)
	assert.Equal(t, []string{"a-at", "s-rt"}, revoked)
	mu.Unlock()
	assert.Len(t, hook.AllEntries(), 3, "one line per revoked token, plus the session closed line")
	assert.True(t, closed)
	assert.Nil(t, activeTokenSource.Load())
	assert.Nil(t, ts.Get())
}
