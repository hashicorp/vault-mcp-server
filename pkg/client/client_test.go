// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/hashicorp/vault/api"
	"github.com/mark3labs/mcp-go/mcp"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestGetEnv(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		fallback string
		expected string
	}{
		{
			name:     "returns fallback when env var not set",
			key:      "NON_EXISTENT_VAR",
			fallback: "default_value",
			expected: "default_value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getEnv(tt.key, tt.fallback)
			if result != tt.expected {
				t.Errorf("getEnv() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestHashToken tests the token hashing function for security
func TestHashToken(t *testing.T) {
	tests := []struct {
		name     string
		token    string
		validate func(t *testing.T, hash [32]byte)
	}{
		{
			name:  "empty string produces valid hash",
			token: "",
			validate: func(t *testing.T, hash [32]byte) {
				assert.Equal(t, 32, len(hash))
			},
		},
		{
			name:  "same token produces same hash (deterministic)",
			token: "test-token-123",
			validate: func(t *testing.T, hash [32]byte) {
				hash2 := hashToken("test-token-123")
				assert.Equal(t, hash, hash2)
			},
		},
		{
			name:  "different tokens produce different hashes",
			token: "token-1",
			validate: func(t *testing.T, hash [32]byte) {
				hash2 := hashToken("token-2")
				assert.NotEqual(t, hash, hash2)
			},
		},
		{
			name:  "hash length is always 32 bytes",
			token: "very-long-token-with-many-characters-to-test-hash-length",
			validate: func(t *testing.T, hash [32]byte) {
				assert.Equal(t, 32, len(hash))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := hashToken(tt.token)
			tt.validate(t, hash)
		})
	}
}

// TestGetVaultClient tests retrieving cached Vault clients
func TestGetVaultClient(t *testing.T) {
	t.Run("returns nil when session doesn't exist", func(t *testing.T) {
		client := GetVaultClient("non-existent-session")
		assert.Nil(t, client)
	})

	t.Run("returns client when session exists", func(t *testing.T) {
		sessionID := "test-session-get"
		vaultAddress := "http://127.0.0.1:8200"
		vaultToken := "test-token"

		// Create a client
		_, err := NewVaultClient(sessionID, vaultAddress, false, vaultToken, "")
		assert.NoError(t, err)

		// Retrieve it
		client := GetVaultClient(sessionID)
		assert.NotNil(t, client)
		assert.Equal(t, vaultAddress, client.Address())

		// Cleanup
		DeleteVaultClient(sessionID)
	})

	t.Run("returns correct client for specific session", func(t *testing.T) {
		session1 := "session-1"
		session2 := "session-2"
		addr1 := "http://vault1.example.com"
		addr2 := "http://vault2.example.com"

		// Create two different clients
		_, err := NewVaultClient(session1, addr1, false, "token1", "")
		assert.NoError(t, err)
		_, err = NewVaultClient(session2, addr2, false, "token2", "")
		assert.NoError(t, err)

		// Verify each returns correct client
		client1 := GetVaultClient(session1)
		client2 := GetVaultClient(session2)
		assert.NotNil(t, client1)
		assert.NotNil(t, client2)
		assert.Equal(t, addr1, client1.Address())
		assert.Equal(t, addr2, client2.Address())

		// Cleanup
		DeleteVaultClient(session1)
		DeleteVaultClient(session2)
	})
}

// TestGetSessionEntry tests retrieving session entries with token hashes
func TestGetSessionEntry(t *testing.T) {
	t.Run("returns nil when session doesn't exist", func(t *testing.T) {
		entry := getSessionEntry("non-existent-session")
		assert.Nil(t, entry)
	})

	t.Run("returns entry when session exists", func(t *testing.T) {
		sessionID := "test-session-entry"
		vaultToken := "test-token-entry"

		// Create a client
		_, err := NewVaultClient(sessionID, "http://127.0.0.1:8200", false, vaultToken, "")
		assert.NoError(t, err)

		// Retrieve entry
		entry := getSessionEntry(sessionID)
		assert.NotNil(t, entry)
		assert.NotNil(t, entry.client)

		// Cleanup
		DeleteVaultClient(sessionID)
	})

	t.Run("returns entry with correct token hash", func(t *testing.T) {
		sessionID := "test-session-hash"
		vaultToken := "test-token-hash"
		expectedHash := hashToken(vaultToken)

		// Create a client
		_, err := NewVaultClient(sessionID, "http://127.0.0.1:8200", false, vaultToken, "")
		assert.NoError(t, err)

		// Retrieve entry and verify hash
		entry := getSessionEntry(sessionID)
		assert.NotNil(t, entry)
		assert.Equal(t, expectedHash, entry.tokenHash)

		// Cleanup
		DeleteVaultClient(sessionID)
	})
}

// TestDeleteVaultClient tests removing cached Vault clients
func TestDeleteVaultClient(t *testing.T) {
	t.Run("successfully deletes existing session", func(t *testing.T) {
		sessionID := "test-delete-session"

		// Create a client
		_, err := NewVaultClient(sessionID, "http://127.0.0.1:8200", false, "test-token", "")
		assert.NoError(t, err)

		// Verify it exists
		client := GetVaultClient(sessionID)
		assert.NotNil(t, client)

		// Delete it
		DeleteVaultClient(sessionID)

		// Verify it's gone
		client = GetVaultClient(sessionID)
		assert.Nil(t, client)
	})

	t.Run("handles deletion of non-existent session gracefully", func(t *testing.T) {
		// Should not panic
		assert.NotPanics(t, func() {
			DeleteVaultClient("non-existent-session")
		})
	})

	t.Run("subsequent GetVaultClient returns nil after deletion", func(t *testing.T) {
		sessionID := "test-delete-verify"

		// Create, delete, and verify
		_, err := NewVaultClient(sessionID, "http://127.0.0.1:8200", false, "test-token", "")
		assert.NoError(t, err)

		DeleteVaultClient(sessionID)

		client := GetVaultClient(sessionID)
		assert.Nil(t, client)

		entry := getSessionEntry(sessionID)
		assert.Nil(t, entry)
	})
}

// TestResolveVaultToken tests token resolution from context and environment
func TestResolveVaultToken(t *testing.T) {
	t.Run("returns token from context when present", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), contextKey(VaultToken), "context-token")
		token := resolveVaultToken(ctx)
		assert.Equal(t, "context-token", token)
	})

	t.Run("falls back to environment variable when context empty", func(t *testing.T) {
		t.Setenv(VaultToken, "env-token")
		ctx := context.Background()
		token := resolveVaultToken(ctx)
		assert.Equal(t, "env-token", token)
	})

	t.Run("returns empty string when neither context nor env set", func(t *testing.T) {
		// Unset environment variable
		prevVal, wasSet := os.LookupEnv(VaultToken)
		os.Unsetenv(VaultToken)
		t.Cleanup(func() {
			if wasSet {
				os.Setenv(VaultToken, prevVal)
			}
		})

		ctx := context.Background()
		token := resolveVaultToken(ctx)
		assert.Equal(t, "", token)
	})

	t.Run("context takes precedence over environment", func(t *testing.T) {
		t.Setenv(VaultToken, "env-token")
		ctx := context.WithValue(context.Background(), contextKey(VaultToken), "context-token")
		token := resolveVaultToken(ctx)
		assert.Equal(t, "context-token", token)
	})

	t.Run("empty string in context falls back to env", func(t *testing.T) {
		t.Setenv(VaultToken, "env-token")
		ctx := context.WithValue(context.Background(), contextKey(VaultToken), "")
		token := resolveVaultToken(ctx)
		assert.Equal(t, "env-token", token)
	})
}

// TestWithVaultToken tests the context helper function
func TestWithVaultToken(t *testing.T) {
	t.Run("adds token to context correctly", func(t *testing.T) {
		ctx := context.Background()
		token := "test-token-123"

		newCtx := WithVaultToken(ctx, token)

		retrievedToken := newCtx.Value(contextKey(VaultToken))
		assert.Equal(t, token, retrievedToken)
	})

	t.Run("token can be retrieved with correct context key", func(t *testing.T) {
		ctx := WithVaultToken(context.Background(), "my-token")

		// Should work with resolveVaultToken
		token := resolveVaultToken(ctx)
		assert.Equal(t, "my-token", token)
	})

	t.Run("works with background context", func(t *testing.T) {
		ctx := WithVaultToken(context.Background(), "bg-token")
		assert.NotNil(t, ctx)
		assert.Equal(t, "bg-token", ctx.Value(contextKey(VaultToken)))
	})

	t.Run("works with existing context values", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), contextKey("other-key"), "other-value")
		ctx = WithVaultToken(ctx, "new-token")

		assert.Equal(t, "new-token", ctx.Value(contextKey(VaultToken)))
		assert.Equal(t, "other-value", ctx.Value(contextKey("other-key")))
	})

	t.Run("multiple calls create independent contexts", func(t *testing.T) {
		ctx1 := WithVaultToken(context.Background(), "token-1")
		ctx2 := WithVaultToken(context.Background(), "token-2")

		assert.Equal(t, "token-1", ctx1.Value(contextKey(VaultToken)))
		assert.Equal(t, "token-2", ctx2.Value(contextKey(VaultToken)))
	})
}

// TestGetVaultClientFromContext tests the main client retrieval function with security checks
func TestGetVaultClientFromContext(t *testing.T) {
	logger := log.New()
	logger.SetLevel(log.ErrorLevel)

	t.Run("error when no session in context", func(t *testing.T) {
		ctx := context.Background()
		client, err := GetVaultClientFromContext(ctx, logger)
		assert.Error(t, err)
		assert.Nil(t, client)
		assert.Contains(t, err.Error(), "no active session")
	})

	// The following tests verify the security logic of token hash validation
	// by testing the underlying functions that GetVaultClientFromContext uses
	// Note: Full integration testing requires the mcp-go server context setup

	t.Run("token hash validation - matching tokens", func(t *testing.T) {
		sessionID := "test-hash-match"
		token := "test-token-123"

		// Create a client with a token
		_, err := NewVaultClient(sessionID, "http://127.0.0.1:8200", false, token, "")
		assert.NoError(t, err)
		t.Cleanup(func() { DeleteVaultClient(sessionID) })

		// Verify the token hash is stored correctly
		entry := getSessionEntry(sessionID)
		assert.NotNil(t, entry)
		expectedHash := hashToken(token)
		assert.Equal(t, expectedHash, entry.tokenHash)

		// Verify same token produces same hash (security requirement)
		currentHash := hashToken(token)
		assert.Equal(t, entry.tokenHash, currentHash)
	})

	t.Run("token hash validation - different tokens produce different hashes", func(t *testing.T) {
		sessionID := "test-hash-mismatch"
		originalToken := "original-token"
		differentToken := "different-token"

		// Create a client with original token
		_, err := NewVaultClient(sessionID, "http://127.0.0.1:8200", false, originalToken, "")
		assert.NoError(t, err)
		t.Cleanup(func() { DeleteVaultClient(sessionID) })

		// Get the stored hash
		entry := getSessionEntry(sessionID)
		assert.NotNil(t, entry)
		originalHash := entry.tokenHash

		// Verify different token produces different hash
		differentHash := hashToken(differentToken)
		assert.NotEqual(t, originalHash, differentHash)
	})

	t.Run("session isolation - different sessions have independent clients", func(t *testing.T) {
		session1 := "isolated-session-1"
		session2 := "isolated-session-2"
		token1 := "token-1"
		token2 := "token-2"

		// Create two clients
		_, err := NewVaultClient(session1, "http://vault1.example.com", false, token1, "")
		assert.NoError(t, err)
		_, err = NewVaultClient(session2, "http://vault2.example.com", false, token2, "")
		assert.NoError(t, err)
		t.Cleanup(func() {
			DeleteVaultClient(session1)
			DeleteVaultClient(session2)
		})

		// Verify each session has its own client and token hash
		entry1 := getSessionEntry(session1)
		entry2 := getSessionEntry(session2)
		assert.NotNil(t, entry1)
		assert.NotNil(t, entry2)
		assert.NotEqual(t, entry1.client, entry2.client)
		assert.NotEqual(t, entry1.tokenHash, entry2.tokenHash)
	})
}

func TestNewVaultClient(t *testing.T) {
	// This is a basic test that checks if the function doesn't panic
	// In a real scenario, you'd want to mock the Vault API
	sessionID := "test-session"
	vaultAddress := "http://127.0.0.1:8200"
	vaultToken := "test-token"
	vaultNamespace := "test-namespace"

	client, err := NewVaultClient(sessionID, vaultAddress, false, vaultToken, vaultNamespace)
	if err != nil {
		t.Logf("NewVaultClient() error = %v (expected in test environment)", err)
	}

	if client != nil {
		// Clean up
		DeleteVaultClient(sessionID)
	}
}

// mockClientSession implements server.ClientSession for testing.
type mockClientSession struct {
	id string
}

func (m *mockClientSession) Initialize()                                        {}
func (m *mockClientSession) Initialized() bool                                  { return true }
func (m *mockClientSession) NotificationChannel() chan<- mcp.JSONRPCNotification { return make(chan mcp.JSONRPCNotification, 1) }
func (m *mockClientSession) SessionID() string                                  { return m.id }

// contextWithSession adds a mock session to the context using reflection to match
// the internal context key used by mcp-go/server package
func contextWithSession(ctx context.Context, session *mockClientSession) context.Context {
	// The server package uses an unexported context key, so we need to use
	// a workaround. We'll create a context that returns our session when
	// server.ClientSessionFromContext is called.
	// Since we can't access the internal key, we'll test the functions that
	// don't require GetVaultClientFromContext or use CreateVaultClientForSession directly
	return context.WithValue(ctx, contextKey("mcp.client.session"), session)
}

func TestCreateVaultClientForSession_SkipTLSVerify(t *testing.T) {
	logger := log.New()
	logger.SetLevel(log.WarnLevel)

	newCtx := func(vals map[contextKey]string) context.Context {
		ctx := context.Background()
		for k, v := range vals {
			ctx = context.WithValue(ctx, k, v)
		}
		return ctx
	}

	getTLSSkip := func(t *testing.T, c *api.Client) bool {
		t.Helper()
		httpClient := c.CloneConfig().HttpClient
		tr, ok := httpClient.Transport.(*http.Transport)
		if !ok || tr.TLSClientConfig == nil {
			return false
		}
		return tr.TLSClientConfig.InsecureSkipVerify
	}

	baseCtx := map[contextKey]string{
		contextKey(VaultAddress): "http://127.0.0.1:8200",
		contextKey(VaultToken):   "test-token",
	}

	t.Run("env var fallback when context key absent", func(t *testing.T) {
		t.Setenv(VaultSkipTLSVerify, "true")

		session := &mockClientSession{id: "test-env-fallback"}
		client, err := CreateVaultClientForSession(newCtx(baseCtx), session, logger)
		assert.NoError(t, err)
		assert.True(t, getTLSSkip(t, client), "expected InsecureSkipVerify=true from env fallback")
		DeleteVaultClient(session.id)
	})

	t.Run("context true takes precedence over env false", func(t *testing.T) {
		t.Setenv(VaultSkipTLSVerify, "false")

		ctxVals := map[contextKey]string{
			contextKey(VaultAddress):      "http://127.0.0.1:8200",
			contextKey(VaultToken):        "test-token",
			contextKey(VaultSkipTLSVerify): "true",
		}
		session := &mockClientSession{id: "test-ctx-true-env-false"}
		client, err := CreateVaultClientForSession(newCtx(ctxVals), session, logger)
		assert.NoError(t, err)
		assert.True(t, getTLSSkip(t, client), "context true should win over env false")
		DeleteVaultClient(session.id)
	})

	t.Run("context false takes precedence over env true", func(t *testing.T) {
		t.Setenv(VaultSkipTLSVerify, "true")

		ctxVals := map[contextKey]string{
			contextKey(VaultAddress):      "http://127.0.0.1:8200",
			contextKey(VaultToken):        "test-token",
			contextKey(VaultSkipTLSVerify): "false",
		}
		session := &mockClientSession{id: "test-ctx-false-env-true"}
		client, err := CreateVaultClientForSession(newCtx(ctxVals), session, logger)
		assert.NoError(t, err)
		assert.False(t, getTLSSkip(t, client), "context false should win over env true")
		DeleteVaultClient(session.id)
	})

	t.Run("defaults to false when neither context nor env set", func(t *testing.T) {
		prevVal, wasSet := os.LookupEnv(VaultSkipTLSVerify)
		os.Unsetenv(VaultSkipTLSVerify)
		t.Cleanup(func() {
			if wasSet {
				os.Setenv(VaultSkipTLSVerify, prevVal)
			}
		})

		session := &mockClientSession{id: "test-default-false"}
		client, err := CreateVaultClientForSession(newCtx(baseCtx), session, logger)
		assert.NoError(t, err)
		assert.False(t, getTLSSkip(t, client), "should default to InsecureSkipVerify=false")
		DeleteVaultClient(session.id)
	})

	t.Run("invalid context value falls back to env", func(t *testing.T) {
		t.Setenv(VaultSkipTLSVerify, "true")

		ctxVals := map[contextKey]string{
			contextKey(VaultAddress):      "http://127.0.0.1:8200",
			contextKey(VaultToken):        "test-token",
			contextKey(VaultSkipTLSVerify): "not-a-bool",
		}
		session := &mockClientSession{id: "test-invalid-ctx"}
		client, err := CreateVaultClientForSession(newCtx(ctxVals), session, logger)
		assert.NoError(t, err)
		assert.True(t, getTLSSkip(t, client), "invalid context should fall back to env=true")
		DeleteVaultClient(session.id)
	})
}

func TestVaultNamespaceSupport(t *testing.T) {
	logger := log.New()
	logger.SetLevel(log.ErrorLevel)

	t.Run("namespace via header", func(t *testing.T) {
		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			namespace := ctx.Value(contextKey(VaultNamespace))
			assert.Equal(t, "test-namespace", namespace)
			w.WriteHeader(http.StatusOK)
		})

		middleware := VaultContextMiddleware(logger)
		handler := middleware(mockHandler)

		req := httptest.NewRequest("GET", "/mcp", nil)
		req.Header.Set(VaultHeaderNamespace, "test-namespace")

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("namespace via environment variable", func(t *testing.T) {
		os.Setenv(VaultNamespace, "env-namespace")
		defer os.Unsetenv(VaultNamespace)

		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			namespace := ctx.Value(contextKey(VaultNamespace))
			assert.Equal(t, "env-namespace", namespace)
			w.WriteHeader(http.StatusOK)
		})

		middleware := VaultContextMiddleware(logger)
		handler := middleware(mockHandler)

		req := httptest.NewRequest("GET", "/mcp", nil)

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("header takes precedence over environment", func(t *testing.T) {
		os.Setenv(VaultNamespace, "env-namespace")
		defer os.Unsetenv(VaultNamespace)

		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			namespace := ctx.Value(contextKey(VaultNamespace))
			assert.Equal(t, "header-namespace", namespace)
			w.WriteHeader(http.StatusOK)
		})

		middleware := VaultContextMiddleware(logger)
		handler := middleware(mockHandler)

		req := httptest.NewRequest("GET", "/mcp", nil)
		req.Header.Set(VaultHeaderNamespace, "header-namespace")

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})
}
