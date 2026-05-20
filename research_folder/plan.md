# Plan: OIDC Authentication for Vault MCP Server (Requirement 1)

## Overview

Implement OIDC-based authentication for Vault MCP Server enabling users to authenticate with enterprise identity (via OIDC provider) and exchange JWT tokens for Vault tokens. The system will validate user permissions, expose only authorized tools, gate write operations with human approval, and maintain full audit traceability.

**Approach**: Incremental delivery in 3 phases:
- Phase 1: Core OIDC auth flow + JWT-to-Vault token exchange
- Phase 2: Policy-based dynamic tool filtering  
- Phase 3: Proactive token refresh + HITL approval for write operations

**Key Architecture**: Insert OIDC authentication before session establishment, leverage existing session hooks for Vault client creation, use middleware for policy evaluation and approval gating.

---

## Phase 1: Core OIDC Authentication & JWT Exchange

### Goal
Enable users to authenticate via OIDC browser flow, exchange JWT for Vault token, and establish authenticated MCP sessions with full audit logging.

### Steps

1. **Create OIDC configuration module** (*no dependencies*)
   - New file: `pkg/auth/oidc_config.go`
   - Load OIDC settings from env vars: issuer URL, client ID, client secret, scopes, redirect URI template
   - Add Vault JWT auth mount path config (default: `/auth/jwt`, override via `VAULT_JWT_AUTH_PATH`)
   - Validation logic for required OIDC parameters

2. **Implement OIDC authentication flow** (*depends on step 1*)
   - New file: `pkg/auth/oidc_client.go`
   - Use `golang.org/x/oauth2` for OIDC flow
   - Functions: `InitOIDCProvider()`, `StartAuthFlow()`, `HandleCallback()`, `ExchangeCode()`
   - Generate PKCE challenge for security
   - Launch browser for user authentication
   - Parse and validate ID token JWT

3. **Implement OAuth callback server** (*depends on step 2*)
   - New file: `pkg/auth/callback_server.go`
   - **HTTP mode**: Add `/auth/callback` endpoint to existing MCP HTTP server
   - **Stdio mode**: Launch ephemeral HTTP server on random port (8000-9000 range)
   - Callback handler: receive auth code, trigger exchange, return success/error page
   - Lifecycle: reuse MCP server when available, else ephemeral with cleanup

4. **Implement JWT-to-Vault token exchange** (*depends on step 2*)
   - New file: `pkg/auth/vault_jwt_exchange.go`  
   - Function: `ExchangeJWTForVaultToken(jwtToken, vaultAddr, jwtAuthPath) (*api.Client, error)`
   - Call Vault's JWT auth endpoint: `POST /v1/auth/{jwt_mount}/login`
   - Extract Vault token, TTL, policies, entity metadata from response
   - Create authenticated Vault client with token
   - Store token metadata (TTL, refresh time) for Phase 3

5. **Validate JWT auth method on startup** (*depends on step 4*)
   - New file: `pkg/auth/vault_jwt_validation.go`
   - Function: `ValidateJWTAuthConfigured(vaultAddr, jwtAuthPath) error`
   - Use anonymous/bootstrap token to check `sys/auth/{jwt_mount}`
   - Return clear error if JWT auth not enabled with setup instructions
   - Call during server initialization in `cmd/vault-mcp-server/init.go`

6. **Integrate OIDC into session initialization** (*depends on steps 1-5*)
   - Modify: `pkg/client/client.go` - `NewSessionHandler()`
   - Check if OIDC configured (env vars present)
   - If yes: trigger OIDC flow → exchange JWT → get Vault token
   - If no: fall back to existing static token logic (coexistence mode)
   - On OIDC auth failure: reject session establishment with clear error

7. **Store user identity in session context** (*depends on step 6*)
   - Modify: `pkg/client/client.go`
   - Extend session storage to include: JWT claims, Vault token metadata, user identity (subject, email)
   - Function: `GetUserIdentityFromSession(sessionID) (*UserIdentity, error)`
   - Store in `activeClients` map alongside Vault client

8. **Enhance audit logging with user identity** (*depends on step 7*)
   - Modify: `pkg/client/middleware.go` - `LoggingMiddleware()`
   - Modify: All tool handlers in `pkg/tools/` to log before execution
   - Log fields: timestamp, user subject, user email, all non-sensitive JWT claims, tool name, input parameters, result/error, session ID
   - Structured logging format for SIEM integration

9. **Update server initialization** (*depends on steps 1-8*)
   - Modify: `cmd/vault-mcp-server/main.go`
   - Load OIDC config during startup
   - Validate JWT auth method if OIDC configured
   - Register callback endpoint for HTTP mode
   - Update startup logs with auth mode (OIDC vs static token)

10. **Configuration documentation** (*parallel with all steps above*)
    - Update: `README.md`
    - Document new env vars: `VAULT_OIDC_ISSUER`, `VAULT_OIDC_CLIENT_ID`, `VAULT_OIDC_CLIENT_SECRET`, `VAULT_OIDC_SCOPES`, `VAULT_JWT_AUTH_PATH`, `VAULT_OIDC_REDIRECT_URI`
    - Provide setup guide for Vault JWT auth method
    - Example configurations for common OIDC providers (Okta, Auth0, Azure AD)

### Verification

1. **Positive Test - Stdio Mode OIDC Auth**: Set OIDC env vars, start server in stdio mode, verify browser launches, complete OIDC flow, verify MCP session established with JWT-derived Vault token
2. **Positive Test - HTTP Mode OIDC Auth**: Set OIDC env vars, start server in HTTP mode, connect MCP client, verify `/auth/callback` receives code, session established
3. **Positive Test - Static Token Fallback**: Clear OIDC env vars, set `VAULT_TOKEN`, verify session uses static token (backward compatibility)
4. **Negative Test - Invalid OIDC Config**: Set invalid issuer URL, verify session establishment fails with clear error message
5. **Negative Test - JWT Auth Not Enabled**: Start server with OIDC config but Vault JWT auth disabled, verify startup validation fails with helpful error
6. **Negative Test - Failed OIDC Exchange**: Simulate OIDC callback failure, verify session rejected, verify error logged with user identity fields (nulls acceptable here)
7. **Audit Test**: Perform multiple tool operations, verify logs contain JWT subject, email, non-sensitive claims, tool names, parameters
8. **Concurrent Session Test**: Attempt second session while first active, verify rejection (single session mode)

---

## Phase 2: Policy-Based Dynamic Tool Filtering

### Goal
Query user's Vault permissions and expose only authorized tools, hiding tools for inaccessible mounts/paths.

### Steps

1. **Create policy evaluation module** (*depends on Phase 1*)
   - New file: `pkg/auth/policy_evaluator.go`
   - Function: `EvaluateToolPermissions(vaultClient, logger) (*ToolPermissions, error)`
   - Query Vault token metadata: `POST /v1/auth/token/lookup-self`
   - Extract policies, entity, namespace

2. **Implement capability checking** (*depends on step 1*)
   - In: `pkg/auth/policy_evaluator.go`
   - Function: `CheckPathCapabilities(vaultClient, path string) ([]string, error)`
   - Call `POST /v1/sys/capabilities-self` with path
   - Returns capabilities: ["read", "update", "delete", "list", etc.]
   - Cache results per session to avoid repeated queries

3. **Define tool-to-path mapping** (*depends on step 2*)
   - New file: `pkg/auth/tool_permissions.go`
   - Map each tool to required Vault paths and capabilities:
     - `list_secrets` → `secret/data/*` + ["list"]
     - `read_secret` → `secret/data/*` + ["read"]
     - `write_secret` → `secret/data/*` + ["create", "update"]
     - `delete_secret` → `secret/data/*` + ["delete"]
     - `list_mounts` → `sys/mounts` + ["read"]
     - `create_mount` → `sys/mounts/*` + ["create", "update"]
     - `enable_pki` → `sys/mounts/pki` + ["create", "update"]
     - etc. for all 21 tools
   - Category-level checks: KV (any secret/* access), PKI (any pki/* access), Sys (sys/* access)

4. **Evaluate tool permissions at session start** (*depends on steps 2-3*)
   - Modify: `pkg/client/client.go` - `NewSessionHandler()`
   - After JWT exchange, call `EvaluateToolPermissions(vaultClient)`
   - Store tool permission results in session context
   - Category filtering: if no PKI mount access, hide all PKI tools
   - Selective tool filtering: within accessible categories, hide specific tools without required capabilities

5. **Implement dynamic tool registration** (*depends on step 4*)
   - Modify: `pkg/tools/tools.go` - `InitTools()`
   - Change from static `AddTool()` calls to dynamic registration
   - New function: `RegisterAuthorizedTools(server, toolPermissions, logger)`
   - Only register tools user has permission to use
   - Track registered vs available tools for diagnostics

6. **Add discovery endpoint for visible tools** (*parallel with step 5*)
   - Implement MCP's `tools/list` capability properly
   - Ensure list reflects only accessible tools
   - Add metadata field indicating permission level (read-only vs read-write)

7. **Handle authorization errors gracefully** (*depends on steps 4-5*)
   - Modify: Tool handlers to catch Vault 403 errors
   - Return user-friendly MCP error: "Insufficient permissions for this operation"
   - Log authorization failures with attempted action
   - Runtime authorization serves as safety net for edge cases missed by eager filtering

### Verification

1. **Positive Test - Full Access User**: Authenticate user with admin policy, verify all 21 tools exposed
2. **Positive Test - KV-Only User**: Authenticate user with KV-only policy, verify only KV tools exposed (no PKI, no Sys tools)
3. **Positive Test - Read-Only User**: Authenticate user with read-only policy, verify write/delete tools hidden
4. **Negative Test - No Mount Access**: Authenticate user without PKI mount access, verify PKI category entirely hidden
5. **Negative Test - Path-Level Restriction**: Authenticate user with `secret/data/team-a/*` policy, attempt `secret/data/team-b/*`, verify tool available but operation denied by Vault (runtime authz)
6. **Discovery Test**: Call `tools/list`, verify returned list matches user permissions
7. **Audit Test**: Attempt unauthorized operation, verify audit log shows denied action with user identity

---

## Phase 3: Proactive Token Refresh & HITL Approval

### Goal
Automatically refresh tokens before expiry and require explicit approval for write/delete operations.

### Steps

1. **Implement token TTL monitoring** (*depends on Phase 1*)
   - New file: `pkg/auth/token_refresh.go`
   - Function: `MonitorTokenTTL(sessionID, tokenTTL, refreshCallback)`
   - Background goroutine tracks token TTL
   - Trigger refresh when 80% of TTL elapsed (configurable via `VAULT_TOKEN_REFRESH_THRESHOLD`)
   - Handle token metadata from JWT exchange (stored in Phase 1 step 4)

2. **Implement OIDC refresh token flow** (*depends on step 1*)
   - In: `pkg/auth/oidc_client.go`
   - Function: `RefreshJWT(refreshToken) (*oauth2.Token, error)`
   - Use OIDC refresh token to obtain new JWT without user interaction
   - Store refresh token securely during initial auth (Phase 1)
   - Handle refresh token expiry (fallback to session termination)

3. **Implement Vault token renewal** (*depends on steps 1-2*)
   - In: `pkg/auth/vault_jwt_exchange.go`
   - Function: `RefreshVaultToken(newJWT, vaultClient) error`
   - Exchange new JWT for fresh Vault token
   - Update Vault client's token
   - Reset TTL monitoring
   - Log refresh event with user identity

4. **Integrate token refresh into session** (*depends on steps 1-3*)
   - Modify: `pkg/client/client.go`
   - Start TTL monitoring goroutine after successful auth
   - On refresh trigger: OIDC refresh → JWT exchange → update client
   - On refresh failure: log error, terminate session gracefully
   - Stop monitoring on session end

5. **Define write operation tools** (*no dependencies*)
   - New file: `pkg/auth/tool_classification.go`
   - Classify tools by risk: read-only vs write vs delete
   - Write operations requiring approval:
     - `write_secret`, `delete_secret`
     - `create_mount`, `delete_mount`
     - `enable_pki`, `create_pki_issuer`, `create_pki_role`, `delete_pki_role`, `issue_pki_certificate`

6. **Implement approval prompt mechanism** (*depends on step 5*)
   - New file: `pkg/auth/approval.go`
   - Function: `RequestUserApproval(operation, parameters) (bool, error)`
   - **Stdio mode**: Print approval prompt to stderr, read response from stdin
   - **HTTP mode**: Use MCP's sampling/prompt capability (if available) or return "approval required" error
   - Prompt format: "Approve {tool} with params {params}? [y/N]"
   - Timeout: 30 seconds (configurable via `VAULT_APPROVAL_TIMEOUT`)

7. **Create approval middleware** (*depends on step 6*)
   - New file: `pkg/client/approval_middleware.go`
   - Function: `ApprovalMiddleware(next ToolHandler) ToolHandler`
   - Check if tool requires approval (from step 5 classification)
   - If yes: call `RequestUserApproval()` before executing handler
   - If denied: return error without calling Vault
   - Log approval decisions (approved/denied) with user identity

8. **Integrate approval middleware into tool handlers** (*depends on step 7*)
   - Modify: `pkg/tools/tools.go` - `RegisterAuthorizedTools()`
   - Wrap handlers requiring approval with `ApprovalMiddleware`
   - Configure approval behavior via `VAULT_ENABLE_APPROVAL` (default: true for write ops)
   - Allow disabling approval for specific tools via allowlist

9. **Add approval audit logging** (*depends on steps 7-8*)
   - Modify: `pkg/auth/approval.go` - log approval requests and responses
   - Log fields: user identity, tool, parameters, approval decision, timestamp
   - Enhance tool handler logging to indicate "user-approved" flag

10. **Configuration and testing** (*parallel with all steps above*)
    - Update: `README.md`
    - Document: `VAULT_TOKEN_REFRESH_THRESHOLD`, `VAULT_APPROVAL_TIMEOUT`, `VAULT_ENABLE_APPROVAL`
    - Document approval UX for stdio vs HTTP modes

### Verification

1. **Positive Test - Token Refresh**: Start session, wait for token TTL to reach refresh threshold (or mock time), verify automatic refresh occurs, verify no service disruption
2. **Positive Test - Write Approval Granted**: Invoke `write_secret`, approve prompt, verify secret written
3. **Positive Test - Delete Approval Granted**: Invoke `delete_secret`, approve prompt, verify secret deleted
4. **Negative Test - Write Approval Denied**: Invoke `write_secret`, deny prompt, verify operation canceled, secret not written
5. **Negative Test - Approval Timeout**: Invoke `create_mount`, don't respond to prompt, verify timeout error after 30s
6. **Negative Test - Refresh Failure**: Simulate OIDC refresh token expiry, verify session terminated gracefully with clear message
7. **Audit Test - Approved Operation**: Perform approved write, verify log shows approval grant + operation success
8. **Audit Test - Denied Operation**: Deny write operation, verify log shows approval denial, no Vault call made
9. **Read-Only Test**: Invoke `read_secret`, verify no approval prompt (read ops bypass approval)
10. **Admin Bypass Test**: Configure `VAULT_ENABLE_APPROVAL=false`, verify write ops execute without prompts

---

## Relevant Files

### New Files (to be created)
- `pkg/auth/oidc_config.go` — OIDC configuration loading and validation
- `pkg/auth/oidc_client.go` — OIDC provider interaction, auth flow orchestration
- `pkg/auth/callback_server.go` — OAuth callback handling for stdio/HTTP modes
- `pkg/auth/vault_jwt_exchange.go` — JWT-to-Vault token exchange logic
- `pkg/auth/vault_jwt_validation.go` — Startup validation for JWT auth method
- `pkg/auth/policy_evaluator.go` — Vault policy querying and tool permission evaluation
- `pkg/auth/tool_permissions.go` — Tool-to-path-to-capability mapping
- `pkg/auth/token_refresh.go` — Token TTL monitoring and refresh orchestration
- `pkg/auth/tool_classification.go` — Tool risk classification (read/write/delete)
- `pkg/auth/approval.go` — User approval prompt mechanism
- `pkg/client/approval_middleware.go` — Tool handler approval wrapper

### Modified Files
- [cmd/vault-mcp-server/main.go](cmd/vault-mcp-server/main.go) — Initialize OIDC config, register callback endpoint, validate JWT auth on startup
- [cmd/vault-mcp-server/init.go](cmd/vault-mcp-server/init.go) — Add OIDC env var loading
- [pkg/client/client.go](pkg/client/client.go) — Integrate OIDC flow into `NewSessionHandler()`, store user identity, implement refresh
- [pkg/client/middleware.go](pkg/client/middleware.go) — Enhanced audit logging with JWT claims and user identity
- [pkg/tools/tools.go](pkg/tools/tools.go) — Dynamic tool registration based on permissions, approval middleware integration
- All tool handlers in `pkg/tools/kv/*.go`, `pkg/tools/pki/*.go`, `pkg/tools/sys/*.go` — Enhanced logging with user identity
- [README.md](README.md) — Document OIDC configuration, setup guides, new env vars

### Dependencies (to be added to go.mod)
- `golang.org/x/oauth2` — Generic OAuth2/OIDC client
- `github.com/coreos/go-oidc/v3/oidc` — OIDC provider discovery and ID token validation
- (Existing) `github.com/hashicorp/vault/api` — Already present for Vault client

---

## Decisions

1. **OIDC Configuration**: Generic OIDC parameters (issuer, client ID, secret, scopes) via env vars. Works with any compliant provider (Okta, Auth0, Azure AD, etc.). No provider-specific presets.

2. **Authentication Flow**: Browser-based authorization code flow with PKCE. MCP server launches browser, runs callback server (reuses HTTP server when available, ephemeral for stdio), exchanges code for JWT.

3. **Transport Mode Support**: Both stdio and HTTP modes. Callback server reuses MCP HTTP endpoint when available (`/auth/callback`), else ephemeral server on random port for stdio.

4. **Token Exchange Responsibility**: MCP server exchanges JWT for Vault token by calling Vault's JWT auth endpoint. Client doesn't interact with Vault auth directly.

5. **JWT Auth Mount Path**: Configurable via `VAULT_JWT_AUTH_PATH`, defaults to `/auth/jwt`. Optional discovery validation on startup.

6. **Backward Compatibility**: Coexist with static token auth. If OIDC configured (env vars present), use OIDC. Else fall back to `VAULT_TOKEN`. Enables gradual migration.

7. **Session Binding**: 1:1:1 mapping — each MCP session requires its own OIDC authentication and Vault token. No token sharing across sessions.

8. **Concurrent Sessions**: Single session only (single-user local mode). Second session attempt rejected while first active.

9. **Failed Authentication**: Reject session establishment immediately on auth failure. No degradation to unauthenticated or limited mode.

10. **Policy Evaluation Strategy**: Hybrid approach — category-level filtering (hide all PKI tools if no PKI access) + selective tool-level refinement (hide specific tools without required capabilities) + runtime Vault authorization as safety net.

11. **Policy Evaluation Mechanism**: Use Vault's token capabilities API (`sys/capabilities-self`) to check permissions for tool-required paths. Results cached per session.

12. **Token Refresh**: Automatic proactive refresh at 80% of TTL elapsed. Uses OIDC refresh token to get new JWT, exchanges for new Vault token. On refresh failure, terminate session.

13. **Write Operation Gating**: Human-in-the-loop approval required for write/delete/create operations. Read/list operations execute immediately. Approval via stdin prompt (stdio) or MCP sampling (HTTP).

14. **Approval Timeout**: 30 seconds default, configurable via `VAULT_APPROVAL_TIMEOUT`. Timeout results in operation denial.

15. **Audit Logging**: Log all non-sensitive JWT claims (subject, email, issuer, custom claims, expiry) + tool name + input parameters + result/error + approval decision. Structured format for SIEM integration.

16. **Error Messaging**: Dual-level — detailed logs for operators + user-friendly MCP responses. Example: logs show Vault 403 details, user sees "Insufficient permissions".

17. **Implementation Phasing**: 
    - Phase 1 (MVP): OIDC auth + JWT exchange + audit logging
    - Phase 2: Policy-based tool filtering  
    - Phase 3: Token refresh + HITL approval
    Each phase independently verifiable and deployable.

---

## Further Considerations

### 1. Vault JWT Auth Method Role Configuration

**Question**: Should the MCP server validate or enforce specific role configurations in Vault's JWT auth method (e.g., bound claims, token policies)?

**Recommendation**: Assume Vault admin configures JWT auth role correctly. Server validates JWT auth *exists* but doesn't enforce role specifics. Rationale: Role config is policy decision, varies by org. Provide best-practice docs instead of enforcement.

### 2. Multi-Namespace Support

**Question**: How should the server handle Vault Enterprise namespaces for OIDC/JWT auth?

**Recommendation**: Phase 1 assumes single namespace (root or user-specified via `VAULT_NAMESPACE`). Add multi-namespace support in future milestone if customer demand exists. Requires namespace-aware tool registration and namespace switching logic.

### 3. OIDC Scopes Selection

**Question**: What OAuth scopes should be requested?

**Recommendation**: Default to `openid profile email` (standard OIDC scopes). Allow override via `VAULT_OIDC_SCOPES` for custom claims. Document common org-specific scopes (e.g., `groups` for role mapping).

### 4. Offline Access (Refresh Token)

**Question**: Should `offline_access` scope be requested for refresh tokens?

**Recommendation**: Yes, include in default scopes for Phase 3 token refresh. Without it, refresh won't work and sessions terminate on token expiry. Document that some providers require explicit admin approval for offline_access.

### 5. State Parameter Security

**Question**: How to secure OAuth state parameter against CSRF?

**Recommendation**: Generate cryptographically random state parameter (32 bytes), store in memory with timeout (5 min). Validate state on callback before code exchange. Standard OAuth security practice.

### 6. Tool Approval Persistence

**Question**: Should approval decisions be cached within a session (approve once, execute this tool multiple times)?

**Recommendation**: Phase 3 requires approval per operation (no caching). Consider "approve all for this session" option in future enhancement if UX feedback indicates excessive prompts. Start strict, relax based on usage data.

### 7. Audit Log Destination

**Question**: Where should MCP audit logs be written?

**Recommendation**: Phase 1 writes to stdout/stderr (structured JSON) for container log aggregation. Future: support audit log file (`VAULT_MCP_AUDIT_LOG_FILE`) and/or syslog for compliance environments. Vault's own audit logs capture server-side; MCP logs capture client intent.

### 8. Token Revocation on Session End

**Question**: Should Vault token be revoked when MCP session ends?

**Recommendation**: No automatic revocation in Phase 1-3 (tokens self-expire based on TTL). Consider explicit revocation in future milestone for "emergency disconnect" scenarios. Rationale: Adds complexity, TTL-based expiry sufficient for single-user local mode.
