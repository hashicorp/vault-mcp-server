// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

// Package auth provides MCP tools for interactive Vault login from the chat.
package auth

import (
	"context"
	"fmt"
	"sync"

	"github.com/hashicorp/vault-mcp-server/pkg/auth"
	"github.com/hashicorp/vault-mcp-server/pkg/client"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
)

// loginPhase is the step of the unified login flow.
type loginPhase int

const (
	phaseLoggedOut loginPhase = iota
	phaseSubjectPending
	phaseActorPending
	phaseCompleting
	phaseAuthenticated
	phaseReauthRequired
)

// LoginState holds the login state shared by vault_login and vault_auth_status.
type LoginState struct {
	mu sync.Mutex

	cfg auth.AuthConfig

	phase loginPhase
	// pendingURL is the sign-in URL for the current browser step.
	pendingURL string
	// lastFailure is a short reason shown after a failed sign-in attempt.
	lastFailure string
	cancels     []context.CancelFunc
	// gen identifies the current login attempt; background goroutines from an
	// attempt that was closed or invalidated see a different value and stop.
	gen uint64

	tokenSource *auth.TokenSource

	onReady func(*auth.TokenSource)
	logger  *log.Logger
}

// NewLoginTools creates the login state and returns the vault_login and
// vault_auth_status tools. onReady is called when the TokenSource is ready.
func NewLoginTools(cfg auth.AuthConfig, onReady func(*auth.TokenSource), logger *log.Logger) (
	login, authStatus *ToolDef, closeSession func(),
) {
	s := &LoginState{cfg: cfg, onReady: onReady, logger: logger}
	return s.loginTool(), s.authStatusTool(), s.Close
}

// Close cancels pending login flows and clears the process-wide working session.
func (s *LoginState) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closeLocked()
}

func (s *LoginState) closeLocked() {
	s.resetFlowLocked()
	s.phase = phaseLoggedOut
	if s.tokenSource != nil {
		s.tokenSource.Close()
		s.tokenSource = nil
	}
}

// resetFlowLocked cancels pending browser flows and invalidates their goroutines.
func (s *LoginState) resetFlowLocked() {
	for _, cancel := range s.cancels {
		cancel()
	}
	s.cancels = nil
	s.pendingURL = ""
	s.gen++
}

// failLocked ends the current attempt and returns to logged out.
func (s *LoginState) failLocked(reason string, err error) {
	s.logger.WithError(err).Error(reason)
	s.resetFlowLocked()
	s.phase = phaseLoggedOut
	s.lastFailure = reason
}

func (s *LoginState) invalidateSession(ts *auth.TokenSource) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tokenSource != ts {
		return
	}
	s.closeLocked()
	s.phase = phaseReauthRequired
	client.ClearVaultClients()
	s.logger.Warn("Renewal authorization ended; re-authentication required")
}

// ToolDef pairs an mcp.Tool with its handler, matching the pattern used in this repo.
type ToolDef struct {
	Tool    mcp.Tool
	Handler server.ToolHandlerFunc
}

func (s *LoginState) actorPasswordConfigured() bool {
	return s.cfg.ActorUsername != "" && s.cfg.ActorPassword != ""
}

func (s *LoginState) loginTool() *ToolDef {
	t := mcp.NewTool("vault_login",
		mcp.WithDescription("Sign in to Vault. Returns the sign-in URL for the current step; open it in your browser. Safe to call repeatedly: mid-flow it returns the current URL, and when already signed in it says so."),
	)
	return &ToolDef{Tool: t, Handler: func(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return s.login()
	}}
}

func (s *LoginState) login() (*mcp.CallToolResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch s.phase {
	case phaseAuthenticated:
		return mcp.NewToolResultText("Already authenticated. Call vault_auth_status for details."), nil
	case phaseCompleting:
		return mcp.NewToolResultText("Sign-in is finishing. Call vault_auth_status to confirm."), nil
	case phaseSubjectPending:
		return mcp.NewToolResultText(s.subjectPrompt("Waiting for the human sign-in. ")), nil
	case phaseActorPending:
		return mcp.NewToolResultText(s.actorPrompt()), nil
	}

	flowCtx, cancel := context.WithCancel(context.Background())
	pkceURL, ch, err := auth.StartPKCEFlow(flowCtx, s.cfg.SubjectPKCEConfig(), "Subject")
	if err != nil {
		cancel()
		return nil, fmt.Errorf("starting login: %w", err)
	}
	s.cancels = append(s.cancels, cancel)
	s.pendingURL = pkceURL
	s.lastFailure = ""
	s.phase = phaseSubjectPending
	go s.waitForSubject(s.gen, ch)
	return mcp.NewToolResultText(s.subjectPrompt("")), nil
}

func (s *LoginState) subjectPrompt(prefix string) string {
	next := "After you sign in, a second sign-in URL for the agent appears. Call vault_login again to get it."
	if s.actorPasswordConfigured() {
		next = "After you sign in, the agent is signed in automatically. Call vault_auth_status to confirm."
	}
	return fmt.Sprintf("%sOpen this URL in your browser to sign in as the human user:\n\n%s\n\n%s", prefix, s.pendingURL, next)
}

func (s *LoginState) actorPrompt() string {
	return fmt.Sprintf("Human sign-in complete. Open this URL in your browser to sign in as the agent:\n\n%s\n\nAfter signing in, call vault_auth_status to confirm.", s.pendingURL)
}

func (s *LoginState) authStatusTool() *ToolDef {
	t := mcp.NewTool("vault_auth_status",
		mcp.WithDescription("Check the current Vault authentication status."),
	)
	return &ToolDef{Tool: t, Handler: func(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return mcp.NewToolResultText(s.status()), nil
	}}
}

func (s *LoginState) status() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch s.phase {
	case phaseAuthenticated:
		if jwt := s.tokenSource.Get(); jwt != nil {
			return fmt.Sprintf("Authenticated. sub=%s exp=%s", jwt.Sub, jwt.Exp.Format("2006-01-02T15:04:05Z07:00"))
		}
		return "Authenticated."
	case phaseCompleting:
		return "Sign-in is finishing."
	case phaseSubjectPending:
		return "Waiting for the human sign-in. Call vault_login for the URL."
	case phaseActorPending:
		return s.actorPrompt()
	case phaseReauthRequired:
		return "Re-authentication required. Call vault_login."
	}
	if s.lastFailure != "" {
		return fmt.Sprintf("Not authenticated. The last sign-in failed: %s. Call vault_login to try again.", s.lastFailure)
	}
	return "Not authenticated. Call vault_login to start."
}

// waitForSubject continues the flow once the human sign-in finishes: the agent
// signs in with the password grant when configured, otherwise a second browser
// flow starts automatically.
func (s *LoginState) waitForSubject(gen uint64, ch <-chan auth.PKCEFlowResult) {
	subject := <-ch
	s.mu.Lock()
	if s.gen != gen {
		s.mu.Unlock()
		return
	}
	if subject.Err != nil {
		s.failLocked("human sign-in failed", subject.Err)
		s.mu.Unlock()
		return
	}

	if s.actorPasswordConfigured() {
		s.phase = phaseCompleting
		s.pendingURL = ""
		s.mu.Unlock()
		actor := auth.PasswordGrant(s.cfg.ActorPKCEConfig(), s.cfg.ActorUsername, s.cfg.ActorPassword)
		s.complete(gen, subject, actor)
		return
	}

	flowCtx, cancel := context.WithCancel(context.Background())
	pkceURL, actorCh, err := auth.StartPKCEFlow(flowCtx, s.cfg.ActorPKCEConfig(), "Actor")
	if err != nil {
		cancel()
		s.failLocked("starting agent sign-in failed", err)
		s.mu.Unlock()
		return
	}
	s.cancels = append(s.cancels, cancel)
	s.pendingURL = pkceURL
	s.phase = phaseActorPending
	s.mu.Unlock()

	actor := <-actorCh
	s.complete(gen, subject, actor)
}

// complete runs the STS exchange with both identities' tokens and publishes the
// TokenSource. It must be called without s.mu held.
func (s *LoginState) complete(gen uint64, subject, actor auth.PKCEFlowResult) {
	s.mu.Lock()
	if s.gen != gen {
		s.mu.Unlock()
		return
	}
	if actor.Err != nil {
		s.failLocked("agent sign-in failed", actor.Err)
		s.mu.Unlock()
		return
	}
	s.phase = phaseCompleting
	s.pendingURL = ""
	s.mu.Unlock()

	pkceResult := &auth.PKCEResult{
		SubjectToken:        subject.Token.AccessToken,
		SubjectRefreshToken: subject.Token.RefreshToken,
		ActorToken:          actor.Token.AccessToken,
		ActorRefreshToken:   actor.Token.RefreshToken,
	}
	jwt, err := auth.ExchangeTokens(
		pkceResult.SubjectToken, pkceResult.ActorToken,
		s.cfg.STSEndpoint, s.cfg.STSClientID, s.cfg.STSClientSecret, s.cfg.STSAuthorizationDetails,
	)

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.gen != gen {
		return
	}
	if err != nil {
		s.failLocked("token exchange failed", err)
		return
	}
	ts := auth.NewTokenSource(s.cfg, jwt, pkceResult)
	ts.OnInvalidated(func() { s.invalidateSession(ts) })
	s.tokenSource = ts
	s.phase = phaseAuthenticated
	s.logger.WithFields(log.Fields{"sub": jwt.Sub, "act": jwt.Act.Sub}).Info("vault_login: authentication complete")
	if s.onReady != nil {
		s.onReady(ts)
	}
}
