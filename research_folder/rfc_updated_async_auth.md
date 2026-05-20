# RFC Addendum: Async OIDC Authentication and Bootstrap Token Strategy

## Critical Issues Identified

### Issue 1: OIDC Browser Flow Async vs MCP Synchronous Registration

**Problem**: OIDC browser-based authentication is inherently asynchronous (user redirects to IdP, authenticates, redirects back), but `mcp-go`'s `OnRegisterSession` hook is synchronous. If authentication happens in the hook, the MCP client will timeout waiting for the synchronous response.

**Impact**: Session registration cannot complete, blocking all MCP operations.

### Issue 2: Bootstrap Token for Startup Validation

**Problem**: The RFC proposes validating JWT auth method availability at startup via `sys/auth/(path)`, but this requires an authenticated Vault token. OIDC is meant to replace static tokens, creating a chicken-and-egg problem: what token validates the auth method before users authenticate?

**Impact**: Cannot verify Vault configuration at startup without a bootstrap token.

---

## Solution 1: Pre-Authentication Pattern for Async OIDC

### Architecture Change

**Decouple authentication from MCP session registration** using a pre-authentication pattern:

```
┌─────────────────────────────────────────────────────────────┐
│ Phase 1: Pre-Authentication (Before MCP Connection)        │
├─────────────────────────────────────────────────────────────┤
│ 1. User starts MCP server (stdio/HTTP mode)                │
│ 2. Server starts HTTP listener on localhost:PORT           │
│ 3. Server opens browser to localhost:PORT/auth/start       │
│ 4. User redirects to OIDC provider                         │
│ 5. User authenticates with IdP                             │
│ 6. IdP redirects to localhost:PORT/auth/callback           │
│ 7. Server exchanges JWT for Vault token                    │
│ 8. Server stores session token in secure storage           │
│ 9. Server displays "Authentication complete" message       │
│ 10. User closes browser                                    │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ Phase 2: MCP Session Registration (Synchronous)            │
├─────────────────────────────────────────────────────────────┤
│ 1. MCP client connects to server                           │
│ 2. OnRegisterSession hook executes (synchronous)           │
│ 3. Server retrieves pre-authenticated session token        │
│ 4. Server validates token is still valid                   │
│ 5. Server performs permission evaluation (fast, cached)    │
│ 6. Server returns filtered tool list immediately           │
│ 7. MCP session established                                 │
└─────────────────────────────────────────────────────────────┘
```

### Implementation Details

#### Startup Sequence (stdio mode)

```go
// main.go
func main() {
    // Start HTTP server for OIDC callback
    authServer := startAuthServer(":8080")
    
    // Initiate OIDC flow
    authURL := authServer.GetAuthURL()
    fmt.Fprintf(os.Stderr, "Opening browser for authentication...\n")
    fmt.Fprintf(os.Stderr, "If browser doesn't open, visit: %s\n", authURL)
    browser.Open(authURL)
    
    // Wait for authentication to complete (with timeout)
    session, err := authServer.WaitForAuth(context.Background(), 5*time.Minute)
    if err != nil {
        log.Fatalf("Authentication failed: %v", err)
    }
    
    // Store session for MCP server
    sessionStore.Set(session)
    
    fmt.Fprintf(os.Stderr, "Authentication successful! Starting MCP server...\n")
    
    // Shutdown auth server
    authServer.Shutdown()
    
    // Start MCP server (stdio mode)
    mcpServer := mcp.NewServer(stdio.NewStdioTransport())
    mcpServer.OnRegisterSession(func(ctx context.Context) (*mcp.Session, error) {
        // Fast synchronous path - session already authenticated
        session := sessionStore.Get()
        if session == nil || session.IsExpired() {
            return nil, errors.New("no valid authentication session")
        }
        
        // Quick permission evaluation (cached from pre-auth)
        tools := permissionEvaluator.GetFilteredTools(session)
        
        return &mcp.Session{
            Tools: tools,
            Context: session.Context,
        }, nil
    })
    
    mcpServer.Serve()
}
```

#### Startup Sequence (HTTP mode)

```go
// HTTP mode - authentication endpoint separate from MCP endpoint
func main() {
    // Start combined HTTP server
    mux := http.NewServeMux()
    
    // Authentication endpoints
    mux.HandleFunc("/auth/start", handleAuthStart)
    mux.HandleFunc("/auth/callback", handleAuthCallback)
    mux.HandleFunc("/auth/status", handleAuthStatus)
    
    // MCP endpoint (requires authentication)
    mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
        // Extract session from cookie/header
        session := extractSession(r)
        if session == nil || session.IsExpired() {
            http.Error(w, "Authentication required", http.StatusUnauthorized)
            return
        }
        
        // Handle MCP request with authenticated session
        mcpHandler.ServeHTTP(w, r, session)
    })
    
    http.ListenAndServe(":8080", mux)
}
```

#### Session Storage

```go
// Session storage with expiration
type SessionStore struct {
    mu       sync.RWMutex
    sessions map[string]*AuthSession
}

type AuthSession struct {
    ID           string
    VaultToken   string
    UserIdentity *Identity
    ExpiresAt    time.Time
    Capabilities *CapabilityMatrix
}

func (s *SessionStore) Get() *AuthSession {
    s.mu.RLock()
    defer s.mu.RUnlock()
    
    // For stdio mode, single session
    for _, session := range s.sessions {
        if !session.IsExpired() {
            return session
        }
    }
    return nil
}
```

### User Experience

**stdio mode**:
```bash
$ vault-mcp-server
Opening browser for authentication...
If browser doesn't open, visit: http://localhost:8080/auth/start

[Browser opens, user authenticates]

Authentication successful! Starting MCP server...
MCP server ready on stdio
```

**HTTP mode**:
```bash
$ vault-mcp-server --mode http --port 8080
MCP server starting on http://localhost:8080
Authentication required at: http://localhost:8080/auth/start

[User visits URL in browser, authenticates]

Authentication successful!
MCP endpoint available at: http://localhost:8080/mcp
```

### Advantages

1. **No MCP timeout**: Authentication completes before MCP session registration
2. **Fast session registration**: OnRegisterSession is synchronous and fast (< 100ms)
3. **Better UX**: Clear separation between auth and MCP operations
4. **Token refresh**: Can refresh tokens in background without blocking MCP operations
5. **Multiple sessions**: HTTP mode can support multiple authenticated users

### Token Refresh Strategy

```go
// Background token refresh
func (s *AuthSession) StartRefreshLoop(ctx context.Context) {
    ticker := time.NewTicker(s.RefreshInterval())
    defer ticker.Stop()
    
    for {
        select {
        case <-ticker.C:
            if err := s.RefreshToken(); err != nil {
                log.Printf("Token refresh failed: %v", err)
                // Mark session as expired, require re-auth
                s.MarkExpired()
                return
            }
        case <-ctx.Done():
            return
        }
    }
}
```

---

## Solution 2: Bootstrap Token Strategy

### Three-Tier Token Strategy

**Tier 1: Bootstrap Token (Server Startup)**
- Purpose: Validate Vault configuration at server startup
- Scope: Minimal permissions (read sys/auth, read sys/health)
- Lifecycle: Long-lived, rotated quarterly
- Storage: Environment variable or secure file

**Tier 2: User Session Token (Runtime)**
- Purpose: User-scoped operations during MCP session
- Scope: User's Vault policies
- Lifecycle: Short-lived (1 hour), auto-refreshed
- Storage: In-memory session store

**Tier 3: Operation Token (Optional, Future)**
- Purpose: Scoped to specific operation
- Scope: Minimal permissions for single operation
- Lifecycle: Single-use, expires immediately
- Storage: Not stored, used and discarded

### Bootstrap Token Implementation

#### Configuration

```yaml
# vault-mcp-server.yaml
vault:
  address: https://vault.example.com
  jwt_auth_path: auth/jwt
  namespace: admin
  
  # Bootstrap token for startup validation
  bootstrap_token_env: VAULT_BOOTSTRAP_TOKEN
  
  # What to validate at startup
  startup_validation:
    check_jwt_auth: true
    check_health: true
    check_namespace_access: true

auth:
  method: oidc
  oidc_discovery_url: https://idp.example.com/.well-known/openid-configuration
  # ... rest of OIDC config
```

#### Startup Validation

```go
// Startup validation with bootstrap token
func validateVaultConfig(cfg *Config) error {
    // Get bootstrap token from environment
    bootstrapToken := os.Getenv(cfg.Vault.BootstrapTokenEnv)
    if bootstrapToken == "" {
        return errors.New("bootstrap token not found in environment")
    }
    
    // Create Vault client with bootstrap token
    client, err := vault.NewClient(&vault.Config{
        Address: cfg.Vault.Address,
    })
    if err != nil {
        return fmt.Errorf("failed to create Vault client: %w", err)
    }
    client.SetToken(bootstrapToken)
    client.SetNamespace(cfg.Vault.Namespace)
    
    // Validate JWT auth method exists
    if cfg.StartupValidation.CheckJWTAuth {
        authPath := cfg.Vault.JWTAuthPath
        auths, err := client.Sys().ListAuth()
        if err != nil {
            return fmt.Errorf("failed to list auth methods: %w", err)
        }
        
        if _, exists := auths[authPath+"/"]; !exists {
            return fmt.Errorf("JWT auth method not found at %s", authPath)
        }
        
        log.Printf("✓ JWT auth method validated at %s", authPath)
    }
    
    // Validate Vault health
    if cfg.StartupValidation.CheckHealth {
        health, err := client.Sys().Health()
        if err != nil {
            return fmt.Errorf("Vault health check failed: %w", err)
        }
        
        if health.Sealed {
            return errors.New("Vault is sealed")
        }
        
        log.Printf("✓ Vault health check passed")
    }
    
    // Validate namespace access
    if cfg.StartupValidation.CheckNamespaceAccess {
        // Try to read namespace info
        _, err := client.Logical().Read("sys/namespaces/" + cfg.Vault.Namespace)
        if err != nil {
            return fmt.Errorf("namespace access check failed: %w", err)
        }
        
        log.Printf("✓ Namespace access validated: %s", cfg.Vault.Namespace)
    }
    
    return nil
}
```

#### Bootstrap Token Creation

**Vault policy for bootstrap token**:
```hcl
# bootstrap-mcp-server.hcl
# Minimal permissions for MCP server startup validation

# Read auth methods
path "sys/auth" {
  capabilities = ["read", "list"]
}

path "sys/auth/+/tune" {
  capabilities = ["read"]
}

# Health check
path "sys/health" {
  capabilities = ["read"]
}

# Namespace access (if using namespaces)
path "sys/namespaces/+" {
  capabilities = ["read"]
}

# Read own token info (for validation)
path "auth/token/lookup-self" {
  capabilities = ["read"]
}
```

**Create bootstrap token**:
```bash
# Create policy
vault policy write bootstrap-mcp-server bootstrap-mcp-server.hcl

# Create long-lived token (90 days)
vault token create \
  -policy=bootstrap-mcp-server \
  -period=90d \
  -display-name="mcp-server-bootstrap" \
  -no-default-policy

# Store token securely
export VAULT_BOOTSTRAP_TOKEN="hvs.CAES..."
```

### Alternative: AppRole for Bootstrap

Instead of a static token, use AppRole for bootstrap authentication:

```yaml
# vault-mcp-server.yaml
vault:
  address: https://vault.example.com
  
  # Bootstrap via AppRole
  bootstrap_auth:
    method: approle
    role_id_env: VAULT_ROLE_ID
    secret_id_env: VAULT_SECRET_ID
    mount_path: auth/approle
```

```go
// Bootstrap with AppRole
func bootstrapWithAppRole(cfg *Config) (*vault.Client, error) {
    client, err := vault.NewClient(&vault.Config{
        Address: cfg.Vault.Address,
    })
    if err != nil {
        return nil, err
    }
    
    roleID := os.Getenv(cfg.Vault.BootstrapAuth.RoleIDEnv)
    secretID := os.Getenv(cfg.Vault.BootstrapAuth.SecretIDEnv)
    
    // Authenticate with AppRole
    resp, err := client.Logical().Write(
        cfg.Vault.BootstrapAuth.MountPath+"/login",
        map[string]interface{}{
            "role_id":   roleID,
            "secret_id": secretID,
        },
    )
    if err != nil {
        return nil, fmt.Errorf("AppRole login failed: %w", err)
    }
    
    client.SetToken(resp.Auth.ClientToken)
    return client, nil
}
```

### Security Considerations

**Bootstrap Token Security**:
1. **Minimal Permissions**: Only read access to sys/auth and sys/health
2. **Rotation**: Rotate quarterly via automated process
3. **Storage**: Environment variable or secure secret management
4. **Monitoring**: Alert on bootstrap token usage anomalies
5. **Revocation**: Immediate revocation if compromised

**Separation of Concerns**:
- Bootstrap token: Server startup validation only
- User tokens: All runtime operations
- Never use bootstrap token for user operations

---

## Updated Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                    MCP Server Startup                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. Load configuration                                          │
│  2. Get bootstrap token from environment                        │
│  3. Validate Vault configuration:                               │
│     - JWT auth method exists                                    │
│     - Vault is healthy and unsealed                             │
│     - Namespace access available                                │
│  4. Start HTTP server for OIDC callbacks                        │
│  5. Initiate pre-authentication flow                            │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│              Pre-Authentication (Async)                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. Open browser to localhost:8080/auth/start                   │
│  2. Redirect to OIDC provider                                   │
│  3. User authenticates with IdP                                 │
│  4. IdP redirects to localhost:8080/auth/callback               │
│  5. Exchange JWT for Vault token (user-scoped)                  │
│  6. Evaluate permissions and build capability matrix            │
│  7. Store session in memory                                     │
│  8. Display "Authentication complete"                           │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│         MCP Session Registration (Synchronous)                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. MCP client connects                                         │
│  2. OnRegisterSession hook executes                             │
│  3. Retrieve pre-authenticated session (< 1ms)                  │
│  4. Validate session not expired (< 1ms)                        │
│  5. Return filtered tool list (< 10ms, cached)                  │
│  6. Session established                                         │
│                                                                 │
│  Total time: < 100ms (no timeout risk)                          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│              Runtime Operations                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  - All operations use user session token                        │
│  - Background token refresh (before expiration)                 │
│  - Permission evaluation cached                                 │
│  - Audit logging with user identity                             │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Implementation Changes

### Phase 1 Updates (Weeks 1-2)

**Week 1 Additional Tasks**:
- Implement HTTP server for OIDC callbacks (even for stdio mode)
- Build pre-authentication flow with browser integration
- Create session storage with expiration handling
- Add "waiting for authentication" UI

**Week 2 Additional Tasks**:
- Implement bootstrap token validation at startup
- Add AppRole bootstrap authentication option
- Create token refresh background process
- Build session validation for OnRegisterSession

### Configuration Schema Updates

```yaml
# Complete configuration with bootstrap and pre-auth
server:
  mode: stdio  # or http
  port: 8080   # for http mode and OIDC callbacks

vault:
  address: https://vault.example.com
  jwt_auth_path: auth/jwt
  namespace: admin
  
  # Bootstrap authentication for startup validation
  bootstrap_token_env: VAULT_BOOTSTRAP_TOKEN
  # OR
  bootstrap_auth:
    method: approle
    role_id_env: VAULT_ROLE_ID
    secret_id_env: VAULT_SECRET_ID
  
  startup_validation:
    check_jwt_auth: true
    check_health: true
    check_namespace_access: true

auth:
  method: oidc
  
  # Pre-authentication settings
  pre_auth:
    enabled: true
    callback_port: 8080
    callback_path: /auth/callback
    timeout: 5m
    open_browser: true
  
  # OIDC configuration
  oidc_discovery_url: https://idp.example.com/.well-known/openid-configuration
  client_id: vault-mcp-server
  client_secret_env: OIDC_CLIENT_SECRET
  scopes:
    - openid
    - profile
    - email

session:
  ttl: 1h
  refresh_before_expiry: 5m
  max_idle_time: 30m
```

---

## Testing Strategy Updates

### New Test Scenarios

**Pre-Authentication Tests**:
- Pre-auth completes before MCP connection
- Pre-auth timeout handling
- Browser fails to open (manual URL fallback)
- Multiple pre-auth attempts
- Session expiration during pre-auth

**Bootstrap Token Tests**:
- Startup validation with valid bootstrap token
- Startup validation with invalid bootstrap token
- Startup validation with expired bootstrap token
- Bootstrap token with insufficient permissions
- AppRole bootstrap authentication

**Session Registration Tests**:
- Fast synchronous registration (< 100ms)
- Registration with expired session
- Registration with no pre-auth session
- Concurrent registration attempts

---

## Migration Impact

### Breaking Changes

1. **Startup Sequence**: MCP server now requires pre-authentication before accepting connections
2. **Configuration**: New bootstrap token configuration required
3. **User Experience**: Users must complete browser-based auth before MCP operations

### Migration Path

**For Existing Deployments**:
1. Create bootstrap token with minimal permissions
2. Update configuration to include bootstrap_token_env
3. Update startup scripts to handle pre-authentication
4. Test authentication flow in staging environment
5. Deploy to production with user communication

**Backward Compatibility**:
- Provide legacy mode with static token (deprecated, removed in 6 months)
- Clear migration documentation and timeline
- Automated migration tool for configuration updates

---

## Conclusion

These solutions address the critical blocking issues:

1. **Async OIDC**: Pre-authentication pattern decouples async OIDC flow from synchronous MCP registration
2. **Bootstrap Token**: Three-tier token strategy provides startup validation without compromising user token security

The updated architecture maintains all security properties while solving the technical constraints of MCP's synchronous session registration and Vault's authentication requirements.