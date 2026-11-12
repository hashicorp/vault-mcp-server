package auth

import (
	"context"
	"fmt"
	"sync"
	"time"

	coreauth "github.com/hashicorp/vault-mcp-server/pkg/auth"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
)

type pendingLogin struct {
	cancel context.CancelFunc
	url    string
	err    error
	done   bool
}

func RegisterLogin(
	s *server.MCPServer,
	cfg coreauth.AuthConfig,
	store *coreauth.TokenStore,
	logger *log.Logger,
) func() {
	var mu sync.Mutex
	logins := make(map[string]*pendingLogin)
	closed := false
	closeLogin := func() {
		mu.Lock()
		defer mu.Unlock()
		closed = true
		for id, login := range logins {
			login.cancel()
			delete(logins, id)
		}
	}
	s.GetHooks().AddOnUnregisterSession(func(_ context.Context, session server.ClientSession) {
		mu.Lock()
		defer mu.Unlock()
		if login := logins[session.SessionID()]; login != nil {
			login.cancel()
			delete(logins, session.SessionID())
		}
	})
	s.AddTool(
		mcp.NewTool("vault_login_subject",
			mcp.WithDescription(
				"Start user login and return a sign-in URL immediately. After signing in, call vault_auth_status once to check completion.",
			),
		),
		func(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			session := server.ClientSessionFromContext(ctx)
			if session == nil {
				return mcp.NewToolResultError("No active MCP session."), nil
			}
			mu.Lock()
			defer mu.Unlock()
			if closed {
				return mcp.NewToolResultError("Login service is shutting down."), nil
			}
			id := session.SessionID()
			if login := logins[id]; login != nil && !login.done {
				return mcp.NewToolResultText("Login already in progress. Open:\n" + login.url), nil
			}
			acquirer, err := coreauth.NewAcquirer(cfg)
			if err != nil {
				logger.WithError(err).Error("Login provider selection failed")
				return mcp.NewToolResultError("Login provider configuration failed."), nil
			}

			interactive, ok := acquirer.(coreauth.InteractiveTokenAcquirer)
			if !ok {
				return mcp.NewToolResultError("This provider does not support interactive login."), nil
			}
			timeout := cfg.Deadline
			if timeout <= 0 {
				timeout = 5 * time.Minute
			}
			// User interaction continues after this tool request returns.
			flowCtx, cancel := context.WithTimeout(context.Background(), timeout+time.Minute)
			url, results, err := interactive.StartLogin(flowCtx)
			if err != nil {
				cancel()
				logger.WithError(err).Error("Login failed")
				return mcp.NewToolResultError("Login failed. Check server logs."), nil
			}
			login := &pendingLogin{cancel: cancel, url: url}
			logins[id] = login
			go func() {
				defer cancel()
				var result coreauth.LoginResult
				select {
				case result = <-results:
				case <-flowCtx.Done():
					result.Err = flowCtx.Err()
				}
				mu.Lock()
				defer mu.Unlock()
				if closed || logins[id] != login {
					return
				}
				login.done = true
				if result.Err == nil && (result.JWT == nil || result.JWT.Raw == "") {
					result.Err = fmt.Errorf("login returned an empty delegation JWT")
				}
				login.err = result.Err
				if result.Err != nil {
					logger.WithError(result.Err).Error("Login failed")
					return
				}
				store.Set(id, result.JWT)
				logger.Info("Login completed")
			}()
			return mcp.NewToolResultText("Open this URL to sign in:\n\n" + url +
				"\n\nAfter signing in, call vault_auth_status to confirm. Do not poll with terminal commands."), nil
		},
	)
	s.AddTool(mcp.NewTool("vault_auth_status",
		mcp.WithDescription("Check login completion after browser sign-in. Does not start another login.")),
		func(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			session := server.ClientSessionFromContext(ctx)
			if session == nil {
				return mcp.NewToolResultError("No active MCP session."), nil
			}
			mu.Lock()
			defer mu.Unlock()
			if login := logins[session.SessionID()]; login != nil {
				if !login.done {
					return mcp.NewToolResultText("Login in progress. Complete browser sign-in before checking again."), nil
				}
				if login.err != nil {
					return mcp.NewToolResultError("Login failed. Check server logs and call vault_login_subject to retry."), nil
				}
			}
			if jwt, ok := store.Get(session.SessionID()); ok {
				return mcp.NewToolResultText(fmt.Sprintf("Authenticated as %s; expires %s.", jwt.Sub, jwt.Exp.Format(time.RFC3339))), nil
			}
			return mcp.NewToolResultText("Not authenticated or token expired. Call vault_login_subject."), nil
		})
	return closeLogin
}
