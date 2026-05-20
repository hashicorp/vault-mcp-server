# Vault MCP Server Codebase Exploration

## Key Findings

### 1. Current Authentication Mechanism
- **Static token-based**: Currently uses `VAULT_TOKEN` env var or `X-Vault-Token` header
- **Token extraction hierarchy**: HTTP header > Query parameter (disallowed for token) > Environment variable
- **Client storage**: Session-based client storage using `sync.Map` in `activeClients`
- **Functions involved**:
  - `NewVaultClient()` - Creates Vault API client for session
  - `GetVaultClientFromContext()` - Retrieves client from MCP context
  - `CreateVaultClientForSession()` - Creates new client with various auth params
  - `NewSessionHandler()` / `EndSessionHandler()` - Session lifecycle hooks

### 2. MCP Server Initialization Flow
- **Entry**: `main.go` with two modes: stdio (default) and streamable-http
- **Server creation**: `NewServer()` in main.go creates MCPServer with hooks
- **Session hooks**: Registered via `server.Hooks`:
  - `OnRegisterSession` → calls `NewSessionHandler()` to create Vault client
  - `OnUnregisterSession` → calls `EndSessionHandler()` to cleanup
- **Tools initialization**: `tools.InitTools()` called after server creation
- **Startup flow**: 
  1. Parse env vars / CLI flags
  2. Create logger
  3. Create MCPServer with rate limiting + session hooks
  4. Register all tools
  5. Start appropriate transport (stdio or HTTP)

### 3. Tool Exposure & Registration
- **Location**: `pkg/tools/tools.go:InitTools()`
- **Pattern**: Each tool is created with `ToolName()` function returning `server.ServerTool`
- **Tool registration**: `hcServer.AddTool(tool.Tool, tool.Handler)`
- **Tool categories**:
  - KV: list_secrets, read_secret, write_secret, delete_secret
  - PKI: enable_pki, create_pki_issuer, list_pki_issuers, read_pki_issuer, list_pki_roles, read_pki_role, create_pki_role, delete_pki_role, issue_pki_certificate
  - Sys: list_mounts, create_mount, delete_mount

### 4. Client Package Details
- **Main file**: `pkg/client/client.go`
- **Responsibilities**:
  - Create/retrieve/delete Vault clients per session
  - Extract auth credentials from context
  - Initialize Vault API clients with TLS config
  - Set namespace if provided
- **Constants**: VaultAddress, VaultToken, VaultNamespace, VaultSkipTLSVerify
- **Default Vault address**: `http://127.0.0.1:8200`

### 5. Session Management
- **Session storage**: `sync.Map` - thread-safe per-session Vault clients
- **Session lifecycle**:
  - On register: Create new Vault client via context values
  - During execution: Get client from map using SessionID
  - On unregister: Delete client from map
- **SessionID source**: Extracted via `server.ClientSessionFromContext(ctx)`
- **Context-based config**: Vault credentials passed through request context in HTTP mode

### 6. Configuration Options
- **Environment variables**:
  - Transport: `TRANSPORT_MODE`, `TRANSPORT_HOST`, `TRANSPORT_PORT`
  - Vault: `VAULT_ADDR`, `VAULT_TOKEN`, `VAULT_NAMESPACE`, `VAULT_SKIP_VERIFY`
  - MCP: `MCP_ENDPOINT`, `MCP_ALLOWED_ORIGINS`, `MCP_CORS_MODE`
  - TLS: `MCP_TLS_CERT_FILE`, `MCP_TLS_KEY_FILE`
  - Rate limiting: `MCP_RATE_LIMIT_GLOBAL`, `MCP_RATE_LIMIT_SESSION`
- **CLI flags** (streamable-http mode): --transport-host, --transport-port, --mcp-endpoint
- **Config loading functions**: 
  - `LoadCORSConfigFromEnv()`
  - `LoadRateLimitConfigFromEnv()`
  - `GetTLSConfigFromEnv()`

### 7. Middleware & Hooks
- **Middleware stack** (http mode):
  1. `SecurityHandler` - CORS validation at entry
  2. `VaultContextMiddleware` - Extracts Vault config from headers/params/env
  3. `LoggingMiddleware` - Structured logging
  4. Rate limiting middleware (tool handler level)
- **Rate limiting**: Global + per-session limiters using `golang.org/x/time/rate`
- **Security features**:
  - TLS configuration with strong ciphers
  - CORS modes: strict, development, disabled
  - Token in query params explicitly disallowed

### 8. Required Hooks for OIDC Integration
- **Hook points already present**:
  - `AddOnRegisterSession()` - Can intercept session creation
  - `AddOnUnregisterSession()` - Can cleanup after session
- **Missing**: Pre-authentication hook before session registration
- **Current flow**: Client session → credentials extracted from context → Vault client created
- **OIDC integration point**: Need middleware/hook to authenticate and exchange JWT for Vault token BEFORE session handler
