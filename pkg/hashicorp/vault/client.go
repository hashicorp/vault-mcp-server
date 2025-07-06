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
	VaultAddress = "VAULT_ADDR"
	VaultToken   = "VAULT_TOKEN"
)

const DefaultVaultAddress = "http://127.0.0.1:8200"

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
		return nil, fmt.Errorf("api.NewClient failed to create Vault client: %v", err)
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
func GetVaultClientFromContext(ctx context.Context, logger *log.Logger) (*api.Client, error) {
	session := server.ClientSessionFromContext(ctx)
	if session == nil {
		return nil, fmt.Errorf("no active session")
	}

	// Log the session ID for debugging
	logger.WithField("session_id", session.SessionID()).Debug("Retrieving Vault client for session")

	// Try to get existing client
	client := GetVaultClient(session.SessionID())
	if client != nil {
		return client, nil
	}

	logger.WithField("session_id", session.SessionID()).Warn("Vault client not found, creating a new one")

	return CreateVaultClientForSession(ctx, session, logger)
}

func CreateVaultClientForSession(ctx context.Context, session server.ClientSession, logger *log.Logger) (*api.Client, error) {

	// Initialize a new Vault client for this session
	vaultAddress, ok := ctx.Value(contextKey(VaultAddress)).(string)
	if !ok || vaultAddress == "" {
		vaultAddress = getEnv(VaultAddress, DefaultVaultAddress)
	}

	vaultToken, ok := ctx.Value(contextKey(VaultToken)).(string)
	if !ok || vaultToken == "" {
		vaultToken = getEnv(VaultToken, "")
		if vaultToken == "" {
			//logger.Warn("Vault token not provided for session")
			return nil, fmt.Errorf("vault token not provided for session")
		}
	}

	newClient, err := NewVaultClient(session.SessionID(), vaultAddress, vaultToken)
	if err != nil {
		return nil, fmt.Errorf("NewVaultClient failed to create Vault client: %v", err)
	}

	logger.WithFields(log.Fields{
		"session_id": session.SessionID(),
		"vault_addr": vaultAddress,
	}).Info("Created Vault client for session")

	return newClient, nil
}

// NewSessionHandler initializes a new Vault client for the session
func NewSessionHandler(ctx context.Context, session server.ClientSession, logger *log.Logger) {

	_, err := CreateVaultClientForSession(ctx, session, logger)
	if err != nil {
		logger.WithError(err).Error("NewSessionHandler failed to create Vault client")
		return
	}
}

// EndSessionHandler cleans up the Vault client when the session ends
func EndSessionHandler(_ context.Context, session server.ClientSession, logger *log.Logger) {
	DeleteVaultClient(session.SessionID())
	logger.WithField("session_id", session.SessionID()).Info("Cleaned up Vault client for session")
}
