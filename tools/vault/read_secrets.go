package tools

import (
	"context"
	"fmt"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

type ServerTool struct {
	Tool    mcp.Tool
	Handler server.ToolHandlerFunc
}

func ReadSecrets() *ServerTool {

	return &ServerTool{
		Tool: mcp.NewTool("echo"),

		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return mcp.NewToolResultText(fmt.Sprintf("Echo: %v", req.GetArguments()["message"])), nil
		},
	}

}
