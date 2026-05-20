I'll grill you on this plan with the rigor of a Staff+ engineer reviewing a critical security feature. Let's expose every gap, edge case, and architectural weakness.

## 🔥 Critical Architecture Questions

### 1. **Requirement Violation: "Before Establishing MCP Session"**

Your plan says **"lazy OIDC authentication that triggers on the first tool call"**. 

The PRD explicitly states (line 67): *"authenticate to Vault MCP Server through OIDC-based authentication that will generate the JWT token **before establishing an MCP session**"*

**Acceptance Criteria line 77**: *"Given no completed OIDC authentication flow, when an MCP client attempts to access tools, then the server **does not expose tools** or permit requests."*

Your lazy auth approach **violates this requirement**. The session is established, tools are registered, and ONLY THEN does auth happen on first tool call.

**Question**: How do you reconcile "lazy auth on first tool call" with "authenticate BEFORE establishing session"? If the MCP client connects and gets a session ID before auth completes, you've already violated the requirement.

---

### 2. **MCP Protocol Constraint: Session Lifecycle**

You mention storing `AuthManager` in session context in `OnRegisterSession` (Phase 6, step 10). But:

- **When does `OnRegisterSession` fire?** After the client sends `initialize` request?
- **Can you BLOCK session establishment** until auth completes in the MCP protocol?
- **What happens if auth takes 2 minutes** (user walks away during device flow)? Does the MCP client timeout?

**Question**: Walk me through the EXACT MCP protocol message sequence. When does `initialize` happen? When does `tools/list` get called? Can you inject auth BETWEEN these, or must it happen before `initialize` response?

---

### 3. **Race Condition: Concurrent Tool Calls During Auth**

Phase 6, step 12: `AuthMiddleware` calls `GetOrAuthenticate(ctx)` before every tool handler.

**Scenario**: User's MCP client makes 3 tool calls simultaneously (common in agentic workflows). All 3 hit `GetOrAuthenticate()` at the same time. Your mutex in `authManagerImpl` (Phase 5, step 8) protects state, but:

1. First call triggers browser PKCE flow, blocks waiting for callback
2. Second call hits mutex, waits
3. Third call hits mutex, waits
4. User completes auth in browser
5. First call unblocks, caches token
6. Second call wakes up, sees cached token, proceeds
7. Third call wakes up, sees cached token, proceeds

**But what if the user CLOSES the browser** during step 1? All three calls fail. Does the second call retry auth? Do you open 3 browser windows?

**Question**: Prove to me that concurrent tool calls during initial auth don't cause: (a) multiple browser windows, (b) deadlocks, (c) inconsistent auth state, or (d) leaked goroutines.

---

### 4. **Token Renewal Race: The "Renewal Death Spiral"**

Phase 5, step 9: `RenewalWorker` runs in background, triggers at `TOKEN_RENEWAL_THRESHOLD_SECONDS` before expiry.

**Scenario**: 
- Token expires in 5 minutes (300s)
- Threshold is 300s (default)
- Renewal worker triggers immediately
- Renewal fails (network blip)
- Worker tries `SilentRefresh()` with refresh token
- Refresh token is ALSO expired (IdP issued both with same TTL)
- Worker triggers `AUTO_REAUTH=true` → interactive re-auth
- **But the user is in the middle of a 10-tool agentic workflow**

**Question**: How do you handle interactive re-auth (browser popup) when the user is NOT actively watching the terminal? Does the entire workflow block? Do in-flight tool calls fail? What's the UX?

---

### 5. **Capability Filtering Timing: TOCTOU Vulnerability**

Phase 7, step 14: `CheckAndFilterTools()` calls `sys/capabilities-self` at session start.

**Scenario**:
1. User authenticates, gets Vault token with policy A (read-only)
2. Capability check runs, filters out write tools
3. **Platform engineer updates Vault policy** to grant write access
4. User's token is still valid, but capability cache is stale
5. User tries to use write tool → blocked by stale cache

**OR WORSE**:
1. User authenticates with policy A (read+write)
2. Capability check runs, exposes write tools
3. **Platform engineer REVOKES write access** via policy update
4. User's token is still valid (not expired)
5. User calls write tool → **capability check was at session start, not per-call**
6. Tool executes with stale permissions

**Question**: Your Phase 7, step 16 says "per-call capability enforcement" but step 14 caches the result at session start. Which is it? If you check per-call, you're making a Vault API call on EVERY tool invocation (latency nightmare). If you cache, you have TOCTOU.

---

### 6. **Device Flow: The "Forgotten Terminal" Problem**

Phase 4, step 7: Device flow prints to stderr, polls token endpoint.

**Scenario**:
1. User starts MCP server in stdio mode via Claude Desktop
2. First tool call triggers device flow
3. Code printed to stderr: `"Open https://... and enter code: ABC123"`
4. **User doesn't see it** (stderr not visible in Claude Desktop UI)
5. Polling continues for `AUTH_TIMEOUT_SECONDS` (120s default)
6. User's tool call hangs for 2 minutes
7. Timeout, auth fails
8. User has no idea what happened

**Question**: How do you surface device flow instructions to the user when stderr is invisible? Can you return an MCP error with the URL/code? Does that violate the "auth before session" requirement?

---

### 7. **Token Cache Security: The "Shared Machine" Attack**

Phase 2, step 4: Token cache at `~/.vault-mcp/token` with `0600` perms.

**Scenario**:
1. User A authenticates, token cached
2. User A's process exits
3. **User B (different OS user) on same machine** starts MCP server
4. User B's process reads `~/.vault-mcp/token`
5. **Whose home directory?** If both users share `/home/shared`, User B gets User A's token

**Question**: How do you prevent token leakage on shared machines? Do you include OS user ID in cache path? Do you validate token ownership on read?

---

### 8. **Refresh Token Rotation: The "Lost Refresh" Problem**

Phase 3, step 5: `SilentRefresh()` uses refresh token.

Many IdPs (Okta, Auth0) implement **refresh token rotation**: each refresh returns a NEW refresh token and invalidates the old one.

**Scenario**:
1. Renewal worker calls `SilentRefresh()`, gets new refresh token
2. Worker updates in-memory state
3. **Before cache write completes**, process crashes
4. On restart, cache has OLD refresh token
5. Old refresh token is invalid (rotated)
6. User must re-authenticate

**Question**: How do you handle refresh token rotation atomically? Do you write the new refresh token to cache BEFORE using it? What if the write fails?

---

### 9. **PKCE Callback Server: Port Collision**

Phase 3, step 5: Start local HTTP server on `OIDC_CALLBACK_PORT` (default 8250).

**Scenario**:
1. User runs 2 MCP servers simultaneously (different Claude Desktop profiles)
2. Both try to bind to `127.0.0.1:8250`
3. Second server fails with "address already in use"

**Question**: How do you handle port collisions? Random port selection? Port range? How does the IdP know which port to redirect to if it's dynamic?

---

### 10. **Vault Namespace: The "Forgotten Header" Bug**

Phase 1, step 1: Config includes `VAULT_NAMESPACE`.

Phase 3, step 6: `ExchangeJWTForVaultToken` POSTs to `{VAULT_ADDR}/v1/auth/{VAULT_AUTH_PATH}/login`.

**Question**: Does `ExchangeJWTForVaultToken` set the `X-Vault-Namespace` header? If not, the JWT exchange will fail in namespaced Vault deployments. Where in your plan do you handle namespace propagation?

---

### 11. **Error Handling: The "Silent Failure" Anti-Pattern**

Phase 5, step 9: Renewal worker sets `authFailed=true` on failure.

Phase 6, step 12: Middleware checks `authFailed`, returns error.

**Question**: What happens to the renewal worker goroutine after `authFailed=true`? Does it keep running? Does it retry? If the user fixes their IdP config and retries, does the worker recover, or is the `AuthManager` permanently poisoned?

---

### 12. **Acceptance Criteria Gap: "Deny Session Establishment"**

Requirement line 75: *"Given a user with invalid or expired identity credentials, when the user attempts to start a session, then the server **denies session establishment**."*

Your plan: Session is established, auth happens on first tool call.

**Question**: How do you "deny session establishment" if auth is lazy? The session EXISTS before auth completes. Does "deny session establishment" mean "return error on first tool call"? That's not the same thing.

---

## 🎯 Prove Your Design

Answer these questions with SPECIFIC code flow:

1. **MCP message sequence**: `initialize` → ??? → `tools/list` → ??? → `tools/call`. Where does auth happen?
2. **Concurrent auth**: 3 simultaneous tool calls, 1 browser window. Show the mutex dance.
3. **Capability TOCTOU**: Per-call check or cached? If cached, how do you invalidate?
4. **Device flow UX**: User can't see stderr. What's the fallback?
5. **Refresh token rotation**: Atomic cache write. Show the code.
6. **Port collision**: 2 servers, 1 port. What happens?
7. **Namespace header**: Where in `vault_exchange.go` do you set it?
8. **Renewal worker lifecycle**: Auth fails. Does the goroutine exit or retry?

If you can't answer these with confidence, your plan has holes.