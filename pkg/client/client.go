// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"sync"

	"github.com/hashicorp/vault/api"
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
)

var (
	activeClients sync.Map
)

const (
	VaultAddress         = "VAULT_ADDR"
	VaultToken           = "VAULT_TOKEN"
	VaultNamespace       = "VAULT_NAMESPACE"
	VaultSkipTLSVerify   = "VAULT_SKIP_VERIFY"
	VaultHeaderToken     = "X-Vault-Token"
	VaultHeaderNamespace = "X-Vault-Namespace"

	// VaultCACert points at a PEM CA bundle used to verify the upstream Vault
	// TLS certificate. VIASATIOCACertFile is the shared Viasat private CA bundle
	// used as a fallback (typically provisioned via an out-of-process bootstrap step).
	VaultCACert        = "VAULT_CACERT"
	VIASATIOCACertFile = "VIASAT_IO_CACERT_FILE"
)

const DefaultVaultAddress = "http://127.0.0.1:8200"

// contextKey is a type alias to avoid lint warnings while maintaining compatibility
type contextKey string

// ContextWithVaultAuth injects Vault connection details into ctx using the same
// keys VaultContextMiddleware/CreateVaultClientForSession read. It is used by the
// OAuth bearer middleware to hand the per-request Vault token (unsealed from the
// bearer access token) to the downstream session/client code. Empty values are
// skipped so existing context/header/env values are not clobbered.
func ContextWithVaultAuth(ctx context.Context, vaultAddress, vaultToken, vaultNamespace string) context.Context {
	if vaultAddress != "" {
		ctx = context.WithValue(ctx, contextKey(VaultAddress), vaultAddress)
	}
	if vaultToken != "" {
		ctx = context.WithValue(ctx, contextKey(VaultToken), vaultToken)
	}
	if vaultNamespace != "" {
		ctx = context.WithValue(ctx, contextKey(VaultNamespace), vaultNamespace)
	}
	return ctx
}

// getEnv retrieves the value of an environment variable or returns a fallback value if not set
func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

// EffectiveCACertFile returns the CA bundle path to trust for upstream Vault TLS,
// preferring VAULT_CACERT and falling back to the shared Viasat private CA bundle
// (VIASAT_IO_CACERT_FILE). It returns "" when neither is configured or the file
// is not present, so a default system trust store is used.
func EffectiveCACertFile() string {
	for _, key := range []string{VaultCACert, VIASATIOCACertFile} {
		path := getEnv(key, "")
		if path == "" {
			continue
		}
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return ""
}

// newConfiguredVaultClient builds a Vault API client with TLS trust configured
// from the Viasat private CA bundle (when present) and the requested skip-verify
// behavior. It does not register the client in activeClients.
func newConfiguredVaultClient(vaultAddress string, vaultSkipTLSVerify bool, vaultToken string, vaultNamespace string) (*api.Client, error) {
	config := api.DefaultConfig()
	config.Address = vaultAddress

	// ConfigureTLS operates on the default cleanhttp *http.Transport, loading
	// RootCAs from CACert (the Viasat private CA bundle when present).
	tlsConfig := &api.TLSConfig{Insecure: vaultSkipTLSVerify}
	if caFile := EffectiveCACertFile(); caFile != "" {
		tlsConfig.CACert = caFile
	}
	if err := config.ConfigureTLS(tlsConfig); err != nil {
		return nil, fmt.Errorf("configure Vault TLS: %w", err)
	}

	// DefaultConfig reads VAULT_SKIP_VERIFY from the environment and ConfigureTLS
	// only ever sets InsecureSkipVerify to true, never back to false. Force the
	// caller-resolved value so an explicit skip=false wins over the env default.
	if tr, ok := config.HttpClient.Transport.(*http.Transport); ok && tr.TLSClientConfig != nil {
		tr.TLSClientConfig.InsecureSkipVerify = vaultSkipTLSVerify
	}

	client, err := api.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("api.NewClient failed to create Vault client: %v", err)
	}

	if vaultToken != "" {
		client.SetToken(vaultToken)
	}

	if vaultNamespace != "" {
		client.SetNamespace(vaultNamespace)
	}

	return client, nil
}

// NewVaultClient creates a new Vault client for the given session
func NewVaultClient(sessionId string, vaultAddress string, vaultSkipTLSVerify bool, vaultToken string, vaultNamespace string) (*api.Client, error) {
	client, err := newConfiguredVaultClient(vaultAddress, vaultSkipTLSVerify, vaultToken, vaultNamespace)
	if err != nil {
		return nil, err
	}

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

// DeleteVaultClient removes the Vault client for the given session and stops
// any background token renewal loop.
func DeleteVaultClient(sessionId string) {
	StopTokenRenewal(sessionId)
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

	vaultNamespace, ok := ctx.Value(contextKey(VaultNamespace)).(string)
	if !ok || vaultNamespace == "" {
		vaultNamespace = getEnv(VaultNamespace, "")
	}

	var vaultSkipTLSVerify bool
	skipProvidedInContext := false
	skipTLSVal := ctx.Value(contextKey(VaultSkipTLSVerify))
	if skipTLSVal != nil {
		skipTLSStr, ok := skipTLSVal.(string)
		if ok {
			parsed, err := strconv.ParseBool(skipTLSStr)
			if err != nil {
				logger.WithFields(log.Fields{
					"session_id": session.SessionID(),
					"value":      skipTLSStr,
				}).Warn("Invalid boolean value for VaultSkipTLSVerify in context; falling back to VAULT_SKIP_VERIFY or its default")
			} else {
				vaultSkipTLSVerify = parsed
				skipProvidedInContext = true
			}
		}
	}
	if !skipProvidedInContext {
		envVal := getEnv(VaultSkipTLSVerify, "false")
		parsed, err := strconv.ParseBool(envVal)
		if err != nil {
			logger.WithFields(log.Fields{
				"session_id": session.SessionID(),
				"value":      envVal,
		}).Warn("Invalid boolean value for VAULT_SKIP_VERIFY; using default value false")
		} else {
			vaultSkipTLSVerify = parsed
		}
	}

	newClient, err := NewVaultClient(session.SessionID(), vaultAddress, vaultSkipTLSVerify, vaultToken, vaultNamespace)
	if err != nil {
		return nil, fmt.Errorf("NewVaultClient failed to create Vault client: %v", err)
	}

	logger.WithFields(log.Fields{
		"session_id": session.SessionID(),
		"vault_addr": vaultAddress,
	}).Info("Created Vault client for session")

	// Keep the Vault token alive for the duration of the working session. Vault
	// token renewal does not change the token string — it only extends the TTL
	// on Vault's side — so the existing MCP bearer token continues to work.
	StartTokenRenewal(session.SessionID(), newClient, logger)

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
