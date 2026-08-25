// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/hashicorp/vault-mcp-server/pkg/auth"
	"github.com/hashicorp/vault/api"
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
)

// sessionEntry caches a Vault client with its token hash. Requires both
// session ID and matching token to prevent session hijacking via leaked IDs.
type sessionEntry struct {
	client    *api.Client
	tokenHash [32]byte
}

var (
	activeClients sync.Map // sessionId -> *sessionEntry
)

func hashToken(token string) [32]byte {
	return sha256.Sum256([]byte(token))
}

const (
	VaultAddress         = "VAULT_ADDR"
	VaultToken           = "VAULT_TOKEN"
	VaultNamespace       = "VAULT_NAMESPACE"
	VaultSkipTLSVerify   = "VAULT_SKIP_VERIFY"
	VaultHeaderToken     = "X-Vault-Token"
	VaultHeaderNamespace = "X-Vault-Namespace"
	VaultAuditDataHeader = "X-Vault-Audit-Data"
)

const DefaultVaultAddress = "http://127.0.0.1:8200"

// contextKey is a type alias to avoid lint warnings while maintaining compatibility
type contextKey string

// delegationJWTKey is the context key for storing a *auth.DelegationJWT.
const delegationJWTKey contextKey = "delegation_jwt"

// WithDelegationJWT returns a context carrying the given DelegationJWT.
// CreateVaultClientForSession reads it to configure the Vault client for the
// OBO delegation path.
func WithDelegationJWT(ctx context.Context, jwt *auth.DelegationJWT) context.Context {
	return context.WithValue(ctx, delegationJWTKey, jwt)
}

// DelegationJWTFromContext extracts the DelegationJWT from ctx, if present.
func DelegationJWTFromContext(ctx context.Context) (*auth.DelegationJWT, bool) {
	jwt, ok := ctx.Value(delegationJWTKey).(*auth.DelegationJWT)
	return jwt, ok && jwt != nil
}

// auditHeaderValue builds the X-Vault-Audit-Data header value for the given JWT.
// Format: {"sub":"<sub>","act":"<act_sub>"}
func auditHeaderValue(jwt *auth.DelegationJWT) string {
	v := struct {
		Sub string `json:"sub"`
		Act string `json:"act"`
	}{Sub: jwt.Sub, Act: jwt.Act.Sub}
	b, _ := json.Marshal(v) // never fails for a plain struct with string fields
	return string(b)
}

// nowFn is the clock used to check JWT expiry. Replaced in tests.
var nowFn = time.Now

// isJWTExpired returns true when the JWT has a non-zero exp that is in the past.
func isJWTExpired(jwt *auth.DelegationJWT) bool {
	return !jwt.Exp.IsZero() && nowFn().After(jwt.Exp)
}

// getEnv retrieves the value of an environment variable or returns a fallback value if not set
func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

// NewVaultClient creates a new Vault client for the given session
func NewVaultClient(sessionId string, vaultAddress string, vaultSkipTLSVerify bool, vaultToken string, vaultNamespace string) (*api.Client, error) {
	// Initialize Vault client
	config := api.DefaultConfig()
	config.Address = vaultAddress

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: vaultSkipTLSVerify},
	}
	config.HttpClient = &http.Client{Transport: tr}

	client, err := api.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("api.NewClient failed to create Vault client: %v", err)
	}

	client.SetToken(vaultToken)

	if vaultNamespace != "" {
		client.SetNamespace(vaultNamespace)
	}

	activeClients.Store(sessionId, &sessionEntry{client: client, tokenHash: hashToken(vaultToken)})

	return client, nil
}

// GetVaultClient retrieves the Vault client for the given session
func GetVaultClient(sessionId string) *api.Client {
	if entry := getSessionEntry(sessionId); entry != nil {
		return entry.client
	}
	return nil
}

// getSessionEntry retrieves the cached client and token hash for verification.
func getSessionEntry(sessionId string) *sessionEntry {
	if value, ok := activeClients.Load(sessionId); ok {
		return value.(*sessionEntry)
	}
	return nil
}

// DeleteVaultClient removes the Vault client for the given session
func DeleteVaultClient(sessionId string) {
	activeClients.Delete(sessionId)
}

// GetVaultClientFromContext extracts Vault client from the MCP context.
//
// JWT path (when a DelegationJWT is present in context):
//   - If the JWT is expired, auth.ErrTokenExpired is returned immediately — no Vault call.
//   - Otherwise CreateVaultClientForSession is called; it will set the JWT as the Vault
//     token and attach the X-Vault-Audit-Data header.
//
// VAULT_TOKEN path (no JWT in context):
//   - The existing token-hash cache validation is used unchanged.
func GetVaultClientFromContext(ctx context.Context, logger *log.Logger) (*api.Client, error) {
	session := server.ClientSessionFromContext(ctx)
	if session == nil {
		return nil, fmt.Errorf("no active session")
	}

	logger.WithField("session_id", session.SessionID()).Debug("Retrieving Vault client for session")

	// JWT path: expiry check happens before any cache lookup.
	if jwt, ok := DelegationJWTFromContext(ctx); ok {
		if isJWTExpired(jwt) {
			return nil, auth.ErrTokenExpired
		}
		// Always rebuild — the JWT raw string is the token; cached hash irrelevant.
		return CreateVaultClientForSession(ctx, session, logger)
	}

	// VAULT_TOKEN path: existing token-hash security validation.
	requestToken := resolveVaultToken(ctx)

	if entry := getSessionEntry(session.SessionID()); entry != nil {
		if requestToken == "" {
			return nil, fmt.Errorf("vault token required for this request")
		}

		currentHash := hashToken(requestToken)
		if subtle.ConstantTimeCompare(entry.tokenHash[:], currentHash[:]) == 1 {
			return entry.client, nil
		}

		// Token mismatch: rebuild client with current token instead of
		// reusing cached client. Vault will reject invalid tokens.
		logger.WithField("session_id", session.SessionID()).Info("Vault token for session changed; rebuilding client")
		return CreateVaultClientForSession(ctx, session, logger)
	}

	logger.WithField("session_id", session.SessionID()).Warn("Vault client not found, creating a new one")
	return CreateVaultClientForSession(ctx, session, logger)
}

// resolveVaultToken resolves the Vault token from request context
// (X-Vault-Token header/query param) or VAULT_TOKEN env var as fallback.
func resolveVaultToken(ctx context.Context) string {
	if v, ok := ctx.Value(contextKey(VaultToken)).(string); ok && v != "" {
		return v
	}
	return getEnv(VaultToken, "")
}

// WithVaultToken returns a context with the given Vault token, using the
// same key as VaultContextMiddleware. Useful for tests and non-HTTP callers.
func WithVaultToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, contextKey(VaultToken), token)
}

func CreateVaultClientForSession(ctx context.Context, session server.ClientSession, logger *log.Logger) (*api.Client, error) {

	// Initialize a new Vault client for this session
	vaultAddress, ok := ctx.Value(contextKey(VaultAddress)).(string)
	if !ok || vaultAddress == "" {
		vaultAddress = getEnv(VaultAddress, DefaultVaultAddress)
	}

	// JWT path: use the raw JWT string as the Vault token and inject audit header.
	if jwt, ok := DelegationJWTFromContext(ctx); ok {
		newClient, err := NewVaultClient(session.SessionID(), vaultAddress, false, jwt.Raw, "")
		if err != nil {
			return nil, fmt.Errorf("NewVaultClient failed (JWT path): %v", err)
		}
		newClient.AddHeader(VaultAuditDataHeader, auditHeaderValue(jwt))

		logger.WithFields(log.Fields{
			"session_id": session.SessionID(),
			"vault_addr": vaultAddress,
			"sub":        jwt.Sub,
		}).Info("Created Vault client for session (JWT delegation path)")

		return newClient, nil
	}

	// VAULT_TOKEN path: existing logic unchanged.
	vaultToken := resolveVaultToken(ctx)
	if vaultToken == "" {
		return nil, fmt.Errorf("vault token not provided for session")
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
