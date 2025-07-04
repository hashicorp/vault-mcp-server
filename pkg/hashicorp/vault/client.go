// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"os"
	"sync"

	"github.com/hashicorp/vault/api"
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
)

var (
	activeClients sync.Map
)

const (
	VaultAddressHeader = "VAULT_ADDR"
	VaultTokenHeader   = "VAULT_TOKEN"
)

// contextKey is a type alias to avoid lint warnings while maintaining compatibility
type contextKey string

// getEnv retrieves the value of an environment variable or returns a fallback value if not set
func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

// NewVaultClient creates a new Vault client for the given session
func NewVaultClient(sessionId string, vaultAddress string, vaultToken string) (*api.Client, error) {
	// Initialize Vault client
	config := api.DefaultConfig()
	config.Address = vaultAddress

	client, err := api.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Vault client: %v", err)
	}

	client.SetToken(vaultToken)

	activeClients.Store(sessionId, client)

	return client, nil
}

// GetVaultClient retrieves the Vault client for the given session
func GetVaultClient(sessionId string) *api.Client {
	if value, ok := activeClients.Load(sessionId); ok {
		return value.(*api.Client)
	}
	return nil
}

// DeleteVaultClient removes the Vault client for the given session
func DeleteVaultClient(sessionId string) {
	activeClients.Delete(sessionId)
}

// GetVaultClientFromContext extracts Vault client from the MCP context
func GetVaultClientFromContext(ctx context.Context) (*api.Client, error) {
	session := server.ClientSessionFromContext(ctx)
	if session == nil {
		return nil, fmt.Errorf("no active session")
	}

	// Try to get existing client
	client := GetVaultClient(session.SessionID())
	if client != nil {
		return client, nil
	}

	// Create new client if it doesn't exist, check ctx first
	// for Vault address and token, otherwise use environment variables
	vaultAddress, ok := ctx.Value(contextKey(VaultAddressHeader)).(string)
	if !ok || vaultAddress == "" {
		vaultAddress = getEnv(VaultAddressHeader, "http://127.0.0.1:8200")
	}
	
	vaultToken, ok := ctx.Value(contextKey(VaultTokenHeader)).(string)
	if !ok || vaultToken == "" {
		vaultToken = getEnv(VaultTokenHeader, "")
		if vaultToken == "" {
			return nil, fmt.Errorf("vault token not provided")
		}
	}

	return NewVaultClient(session.SessionID(), vaultAddress, vaultToken)
}

// NewSessionHandler initializes a new Vault client for the session
func NewSessionHandler(ctx context.Context, session server.ClientSession, logger *log.Logger) {
	// Initialize a new Vault client for this session
	vaultAddress, ok := ctx.Value(contextKey(VaultAddressHeader)).(string)
	if !ok || vaultAddress == "" {
		vaultAddress = getEnv(VaultAddressHeader, "http://127.0.0.1:8200")
	}

	vaultToken, ok := ctx.Value(contextKey(VaultTokenHeader)).(string)
	if !ok || vaultToken == "" {
		vaultToken = getEnv(VaultTokenHeader, "")
		if vaultToken == "" {
			logger.Warn("Vault token not provided for session")
			return
		}
	}

	_, err := NewVaultClient(session.SessionID(), vaultAddress, vaultToken)
	if err != nil {
		logger.WithError(err).Error("Failed to create Vault client for session")
		return
	}

	logger.WithFields(log.Fields{
		"session_id": session.SessionID(),
		"vault_addr": vaultAddress,
	}).Debug("Created Vault client for session")
}

// EndSessionHandler cleans up the Vault client when the session ends
func EndSessionHandler(_ context.Context, session server.ClientSession, logger *log.Logger) {
	DeleteVaultClient(session.SessionID())
	logger.WithField("session_id", session.SessionID()).Debug("Cleaned up Vault client for session")
}
