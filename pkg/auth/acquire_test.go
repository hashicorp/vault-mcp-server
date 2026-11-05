// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package auth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

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
