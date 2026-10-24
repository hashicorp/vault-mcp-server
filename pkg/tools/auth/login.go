package auth

import (
	"context"

	coreauth "github.com/hashicorp/vault-mcp-server/pkg/auth"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
)

func RegisterLogin(
	s *server.MCPServer,
	cfg coreauth.AuthConfig,
	store *coreauth.TokenStore,
	logger *log.Logger,
) {
	s.AddTool(
		mcp.NewTool("vault_login_subject",
			mcp.WithDescription(
				"Sign in as the user and automatically authenticate the agent.",
			),
		),
		func(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			session := server.ClientSessionFromContext(ctx)
			if session == nil {
				return mcp.NewToolResultError("No active MCP session."), nil
			}
			acquirer, err := coreauth.NewAcquirer("ibm-verify")
			if err != nil {
				logger.WithError(err).Error("Login provider selection failed")
				return mcp.NewToolResultError("Login provider configuration failed."), nil
			}

			jwt, err := acquirer.AcquireTokens(ctx, cfg)
			if err != nil {
				logger.WithError(err).Error("Login failed")
				return mcp.NewToolResultError("Login failed. Check server logs."), nil
			}
			if jwt == nil || jwt.Raw == "" {
				logger.Error("Login returned an empty delegation JWT")
				return mcp.NewToolResultError("Login returned an empty token."), nil
			}

			store.Set(session.SessionID(), jwt)
			return mcp.NewToolResultText("Authentication successful."), nil
		},
	)
}
