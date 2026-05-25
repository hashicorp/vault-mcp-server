// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package tools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/vault-mcp-server/pkg/auth"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
)

// AuthStatusResource represents the authentication status resource
type AuthStatusResource struct {
	URI         string
	Name        string
	Description string
	MimeType    string
}

// InitAuthResources initializes authentication-related MCP resources
func InitAuthResources(hcServer *server.MCPServer, authManager auth.AuthManager, logger *log.Logger) {
	if authManager == nil {
		logger.Debug("AuthManager not available, skipping auth resources")
		return
	}

	// Register auth status resource
	authStatusResource := mcp.Resource{
		URI:         "mcp://auth/status",
		Name:        "Authentication Status",
		Description: "Current OIDC authentication status including token expiry and user information",
		MIMEType:    "application/json",
	}

	authStatusHandler := func(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
		logger.WithField("uri", req.Params.URI).Debug("Reading auth status resource")

		// Get auth status
		status := authManager.GetAuthStatus()

		// Convert to JSON
		statusJSON, err := json.MarshalIndent(status, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("failed to marshal auth status: %w", err)
		}

		contents := []mcp.ResourceContents{
			mcp.TextResourceContents{
				URI:      req.Params.URI,
				MIMEType: "application/json",
				Text:     string(statusJSON),
			},
		}

		logger.Debug("Auth status resource read successfully")
		return contents, nil
	}

	hcServer.AddResource(authStatusResource, authStatusHandler)
	logger.Info("Registered MCP resource: mcp://auth/status")
}
