// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

// Package auth provides MCP tools for interactive Vault login from the chat.
package auth

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/hashicorp/vault-mcp-server/pkg/auth"
	"github.com/hashicorp/vault-mcp-server/pkg/client"
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
	subjectCh      <-chan auth.PKCEFlowResult
	actorCh        <-chan auth.PKCEFlowResult
	cancels        []context.CancelFunc
	reauthRequired bool

	// set once login is complete
	tokenSourceReady atomic.Pointer[auth.TokenSource]

	onReady func(*auth.TokenSource)
	logger  *log.Logger
}

// NewLoginTools creates the login state and returns the three tools.
// onReady is called (exactly once) when the TokenSource is ready.
func NewLoginTools(cfg auth.AuthConfig, onReady func(*auth.TokenSource), logger *log.Logger) (
	loginSubject, loginActor, authStatus *ToolDef, closeSession func(),
) {
	s := &LoginState{cfg: cfg, onReady: onReady, logger: logger}
	return s.loginSubjectTool(), s.loginActorTool(), s.authStatusTool(), s.Close
}

// Close cancels pending login flows and clears the process-wide working session.
func (s *LoginState) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closeLocked()
}

func (s *LoginState) closeLocked() {
	for _, cancel := range s.cancels {
		cancel()
	}
	s.cancels = nil
	s.subjectCh, s.actorCh = nil, nil
	s.subjectResult, s.actorResult = nil, nil
	s.tokenSourceReady.Swap(nil).Close()
}

func (s *LoginState) invalidateSession(ts *auth.TokenSource) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tokenSourceReady.Load() != ts {
		return
	}
	s.closeLocked()
	s.reauthRequired = true
	client.ClearVaultClients()
	s.logger.Warn("Renewal authorization ended; re-authentication required")
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
		flowCtx, cancel := context.WithCancel(context.Background())
		pkceURL, ch, err := auth.StartPKCEFlow(flowCtx, s.cfg.SubjectPKCEConfig(), "Subject")
		if err != nil {
			cancel()
			return nil, fmt.Errorf("starting subject login: %w", err)
		}
		s.subjectCh = ch
		s.reauthRequired = false
		s.cancels = append(s.cancels, cancel)
		go s.waitForSubject(ch)
		next := "After signing in, call vault_login_actor."
		if s.cfg.ActorUsername != "" && s.cfg.ActorPassword != "" {
			next = "After signing in, the agent is authenticated automatically. Call vault_auth_status to confirm."
		}
		return mcp.NewToolResultText(fmt.Sprintf("Open this URL in your browser to sign in as the human subject:\n\n%s\n\n%s", pkceURL, next)), nil
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
		flowCtx, cancel := context.WithCancel(context.Background())
		pkceURL, ch, err := auth.StartPKCEFlow(flowCtx, s.cfg.ActorPKCEConfig(), "Actor")
		if err != nil {
			cancel()
			return nil, fmt.Errorf("starting actor login: %w", err)
		}
		s.actorCh = ch
		s.cancels = append(s.cancels, cancel)
		go s.waitForActorAndComplete(ch)
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
		if s.reauthRequired {
			return mcp.NewToolResultText("Re-authentication required. Call vault_login_subject to start."), nil
		}
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

func (s *LoginState) waitForSubject(ch <-chan auth.PKCEFlowResult) {
	res := <-ch
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.subjectCh != ch {
		return
	}
	s.subjectCh = nil
	if res.Err != nil {
		s.logger.WithError(res.Err).Error("Subject PKCE flow failed")
		return
	}
	s.subjectResult = &res

	// Agent credentials configured: authenticate the actor non-interactively
	// (password grant) and finish login without a second browser sign-in.
	if s.cfg.ActorUsername != "" && s.cfg.ActorPassword != "" {
		actor := auth.PasswordGrant(s.cfg.ActorPKCEConfig(), s.cfg.ActorUsername, s.cfg.ActorPassword)
		if actor.Err != nil {
			s.logger.WithError(actor.Err).Error("Actor password login failed")
			return
		}
		s.actorResult = &actor
		s.completeLogin()
	}
}

func (s *LoginState) waitForActorAndComplete(ch <-chan auth.PKCEFlowResult) {
	res := <-ch
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.actorCh != ch {
		return
	}
	s.actorCh = nil
	if res.Err != nil {
		s.logger.WithError(res.Err).Error("Actor PKCE flow failed")
		return
	}
	s.actorResult = &res
	s.completeLogin()
}

// completeLogin runs the STS exchange with the stored subject and actor tokens,
// then publishes the TokenSource. Caller holds s.mu.
func (s *LoginState) completeLogin() {
	pkceResult := &auth.PKCEResult{
		SubjectToken:        s.subjectResult.Token.AccessToken,
		SubjectRefreshToken: s.subjectResult.Token.RefreshToken,
		ActorToken:          s.actorResult.Token.AccessToken,
		ActorRefreshToken:   s.actorResult.Token.RefreshToken,
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
	ts.OnInvalidated(func() { s.invalidateSession(ts) })
	s.tokenSourceReady.Store(ts)
	s.logger.WithFields(log.Fields{"sub": jwt.Sub, "act": jwt.Act.Sub}).Info("vault_login: authentication complete")
	if s.onReady != nil {
		s.onReady(ts)
	}
}
