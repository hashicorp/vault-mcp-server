// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

// Package auth provides MCP tools for interactive Vault login from the chat.
package auth

import (
	"context"
	"fmt"
	"os"
	"sync"
	"sync/atomic"

	"github.com/hashicorp/vault-mcp-server/pkg/auth"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
)

// LoginState holds the in-progress login state shared between the three tools.
// A pointer to one instance is created in NewLoginTools and passed to each tool.
type LoginState struct {
	mu sync.Mutex

	cfg auth.AuthConfig

	// subject and actor results (nil until the flow completes)
	subjectResult *auth.PKCEFlowResult
	actorResult   *auth.PKCEFlowResult

	// channels for pending flows
	subjectCh <-chan auth.PKCEFlowResult
	actorCh   <-chan auth.PKCEFlowResult

	// set once login is complete
	tokenSourceReady atomic.Pointer[auth.TokenSource]

	onReady func(*auth.TokenSource)
	logger  *log.Logger
}

// NewLoginTools creates the login state and returns the three tools.
// onReady is called (exactly once) when the TokenSource is ready.
func NewLoginTools(cfg auth.AuthConfig, onReady func(*auth.TokenSource), logger *log.Logger) (
	loginSubject, loginActor, authStatus *ToolDef,
) {
	s := &LoginState{cfg: cfg, onReady: onReady, logger: logger}
	return s.loginSubjectTool(), s.loginActorTool(), s.authStatusTool()
}

// ToolDef pairs an mcp.Tool with its handler, matching the pattern used in this repo.
type ToolDef struct {
	Tool    mcp.Tool
	Handler server.ToolHandlerFunc
}

func (s *LoginState) loginSubjectTool() *ToolDef {
	t := mcp.NewTool("vault_login_subject",
		mcp.WithDescription("Start subject (human user) login. Returns the Verify sign-in URL. Open it in your browser, sign in, and then call vault_login_actor."),
	)
	return &ToolDef{Tool: t, Handler: func(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.subjectCh != nil {
			return mcp.NewToolResultText("Subject login already in progress. Open the URL already returned, or call vault_auth_status to check."), nil
		}
		if s.tokenSourceReady.Load() != nil {
			return mcp.NewToolResultText("Already authenticated. Call vault_auth_status to confirm."), nil
		}
		pkceURL, ch, err := auth.StartPKCEFlow(context.Background(), auth.PKCEConfig{
			ClientID:     s.cfg.ClientID,
			ClientSecret: s.cfg.ClientSecret,
			AuthURL:      s.cfg.AuthURL,
			TokenURL:     s.cfg.TokenURL,
			RedirectURL:  s.cfg.RedirectURL,
			Scopes:       s.cfg.Scopes,
			Deadline:     s.cfg.Deadline,
		}, "Subject")
		if err != nil {
			return nil, fmt.Errorf("starting subject login: %w", err)
		}
		s.subjectCh = ch
		go s.waitForSubject()
		return mcp.NewToolResultText(fmt.Sprintf("Open this URL in your browser to sign in as the human subject:\n\n%s\n\nAfter signing in, call vault_login_actor.", pkceURL)), nil
	}}
}

func (s *LoginState) loginActorTool() *ToolDef {
	t := mcp.NewTool("vault_login_actor",
		mcp.WithDescription("Start actor (agent) login. Call this after vault_login_subject completes. Returns the Verify sign-in URL for the agent."),
	)
	return &ToolDef{Tool: t, Handler: func(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.subjectResult == nil {
			return mcp.NewToolResultText("Subject login not complete. Call vault_login_subject first and sign in."), nil
		}
		if s.actorCh != nil {
			return mcp.NewToolResultText("Actor login already in progress. Open the URL already returned, or call vault_auth_status to check."), nil
		}
		if s.tokenSourceReady.Load() != nil {
			return mcp.NewToolResultText("Already authenticated. Call vault_auth_status to confirm."), nil
		}
		pkceURL, ch, err := auth.StartPKCEFlow(context.Background(), auth.PKCEConfig{
			ClientID:     s.cfg.ClientID,
			ClientSecret: s.cfg.ClientSecret,
			AuthURL:      s.cfg.AuthURL,
			TokenURL:     s.cfg.TokenURL,
			RedirectURL:  s.cfg.RedirectURL,
			Scopes:       s.cfg.Scopes,
			Deadline:     s.cfg.Deadline,
		}, "Actor")
		if err != nil {
			return nil, fmt.Errorf("starting actor login: %w", err)
		}
		s.actorCh = ch
		go s.waitForActorAndComplete()
		return mcp.NewToolResultText(fmt.Sprintf("Open this URL in your browser to sign in as the agent actor:\n\n%s\n\nAfter signing in, call vault_auth_status to confirm login.", pkceURL)), nil
	}}
}

func (s *LoginState) authStatusTool() *ToolDef {
	t := mcp.NewTool("vault_auth_status",
		mcp.WithDescription("Check the current Vault authentication status."),
	)
	return &ToolDef{Tool: t, Handler: func(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		s.mu.Lock()
		defer s.mu.Unlock()
		if ts := s.tokenSourceReady.Load(); ts != nil {
			jwt := ts.Get()
			if jwt != nil {
				return mcp.NewToolResultText(fmt.Sprintf("Authenticated. sub=%s exp=%s", jwt.Sub, jwt.Exp.Format("2006-01-02T15:04:05Z07:00"))), nil
			}
		}
		if s.actorCh != nil {
			return mcp.NewToolResultText("Actor login in progress. Waiting for callback."), nil
		}
		if s.subjectCh != nil {
			return mcp.NewToolResultText("Subject login in progress. Waiting for callback."), nil
		}
		if s.subjectResult != nil {
			return mcp.NewToolResultText("Subject login complete. Call vault_login_actor."), nil
		}
		return mcp.NewToolResultText("Not authenticated. Call vault_login_subject to start."), nil
	}}
}

func (s *LoginState) waitForSubject() {
	ch := s.subjectCh
	res := <-ch
	s.mu.Lock()
	defer s.mu.Unlock()
	s.subjectCh = nil
	if res.Err != nil {
		s.logger.WithError(res.Err).Error("Subject PKCE flow failed")
		return
	}
	s.subjectResult = &res
}

func (s *LoginState) waitForActorAndComplete() {
	ch := s.actorCh
	res := <-ch
	s.mu.Lock()
	defer s.mu.Unlock()
	s.actorCh = nil
	if res.Err != nil {
		s.logger.WithError(res.Err).Error("Actor PKCE flow failed")
		return
	}
	s.actorResult = &res

	// STS exchange
	pkceResult := &auth.PKCEResult{
		SubjectToken:        s.subjectResult.Token.AccessToken,
		SubjectRefreshToken: s.subjectResult.Token.RefreshToken,
		ActorToken:          res.Token.AccessToken,
		ActorRefreshToken:   res.Token.RefreshToken,
	}
	jwt, err := auth.ExchangeTokens(
		pkceResult.SubjectToken, pkceResult.ActorToken,
		s.cfg.STSEndpoint, s.cfg.STSClientID, s.cfg.STSClientSecret, s.cfg.STSAuthorizationDetails,
	)
	if err != nil {
		s.logger.WithError(err).Error("STS token exchange failed")
		return
	}
	ts := auth.NewTokenSource(s.cfg, jwt, pkceResult)
	s.tokenSourceReady.Store(ts)
	s.logger.WithFields(log.Fields{"sub": jwt.Sub, "act": jwt.Act.Sub}).Info("vault_login: authentication complete")
	// TEMPORARY: print Delegation JWT for PoC/demo; remove before GA (AC-11, AC-14).
	fmt.Fprintf(os.Stderr, "[vault-mcp-server] Delegation JWT acquired (token=%s)\n", jwt.Raw)
	if s.onReady != nil {
		s.onReady(ts)
	}
}
