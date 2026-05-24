## Plan: MCP Authentication Timing Strategy

**TL;DR**: The PRD requires auth BEFORE MCP session, but `OnRegisterSession` is synchronous while OIDC browser flows are async. **Recommended approach**: Pre-authenticate at startup (browser opens before MCP connects), cache token, then `OnRegisterSession` validates cached token synchronously. Lazy auth on tool calls serves as fallback for token expiration only. This meets PRD requirements while avoiding client timeouts.

---

## Analysis: Three Approaches

### ❌ Option 1: Pre-Authenticated Mode
**Flow**: Auth server on separate port → browser auth → cache token → MCP connects  
**Verdict**: PRD-compliant, fast hooks, but extra startup step  
**PRD Match**: ✅ Authenticates BEFORE session  

### ❌ Option 2: Block OnRegisterSession  
**Flow**: Open browser during hook, wait synchronously for callback  
**Verdict**: PRD-compliant but high timeout risk (browsers take 30s-2min)  
**PRD Match**: ✅ Authenticates BEFORE session (technically), ❌ Poor UX + timeout risk

### ❌ Option 3: Lazy Auth on First Tool Call (Your Proposal)
**Flow**: Session exists immediately, auth triggers on first tool invocation  
**Verdict**: Simple, fast, but **violates PRD requirement**  
**PRD Match**: ❌ Session exists without auth, ❌ Tools exposed before auth

**PRD Language** (requirement.md): *"authenticate through OIDC **before establishing an MCP session**"*  
**Acceptance Criteria** (requirement.md): *"Given no completed OIDC authentication flow... server **does not expose tools**"*

---

## ⭐ Recommended: Hybrid Pre-Auth + Lazy Fallback

### Flow

**Startup (Pre-Auth - Preferred Path)**
1. Server starts → check cached token
2. No valid token → start ephemeral HTTP callback (random port)
3. Open browser to OIDC provider (print device code to stderr as fallback)
4. Wait up to 120s for auth completion
5. Cache token securely (`~/.vault-mcp/session-{uid}.json`, 0600)
6. MCP server ready

**Session Registration (Fast Synchronous)**
1. Client connects via stdio/HTTP
2. `OnRegisterSession` hook:
   - Load cached token (< 10ms)
   - Validate not expired
   - Quick capability check (sys/capabilities-self)
   - Filter tools based on user permissions
   - Return immediately (< 100ms total)

**Runtime (Lazy Fallback Only)**
- Tool middleware checks token validity before each call
- If expired → trigger same pre-auth flow (blocks tool execution)
- Concurrent calls wait on shared mutex (only one browser window)

### Why This Meets PRD

✅ **"Auth BEFORE session"**: Pre-auth completes before `OnRegisterSession` returns  
✅ **"Does not expose tools without auth"**: Tools only registered after token validation in hook  
✅ **"Session denied if invalid credentials"**: Hook returns error if no valid token  
✅ **Synchronous hook constraint**: Just loads cached token (no blocking)  
✅ **Browser flow timing**: Happens at startup, not during protocol handshake  

---

## Steps

**Phase 1: Pre-Auth Server Component** (*parallel with Phase 2*)
1. Create pkg/auth/preauth_server.go
2. Implement ephemeral HTTP callback server (random port 8200-8299)
3. PKCE flow with state validation + device code fallback
4. Write token to secure cache with OS UID in filename
5. Auto-shutdown after callback or 120s timeout

**Phase 2: Token Cache Management** (*parallel with Phase 1*)
1. Create pkg/auth/token_cache.go
2. Cache structure: `{"token": "...", "expires_at": "...", "refresh_token": "...", "claims": {...}}`
3. Location: `$HOME/.vault-mcp/session-{os-uid}.json` (0600 permissions)
4. Functions: `GetCachedToken()`, `SaveToken()`, `IsExpired()`, `ClearCache()`
5. Include OS UID to prevent cross-user token leakage

**Phase 3: Session Hook Integration** (*depends on 1, 2*)
1. Update main.go `NewSessionHandler()`
2. In `OnRegisterSession` hook:
   - Call `auth.GetCachedToken()` → load from cache
   - Validate token expiry
   - Query Vault capabilities (sys/capabilities-self) for user
   - Filter tools list based on capabilities
   - Store auth context in session metadata
   - Return error if no valid token (blocks session creation)

**Phase 4: Tool Middleware Enhancement** (*depends on 2*)
1. Update middleware.go `AuthMiddleware`
2. Before each tool call:
   - Extract session auth context
   - Check token expiry time
   - If expired → call `ReAuthenticate(ctx)` (triggers pre-auth flow, blocks)
   - Validate per-tool capability (not just session-level)
   - Inject Vault token into tool context

**Phase 5: Startup Flow** (*depends on 1, 2*)
1. Update main.go before MCP start
2. Check for cached valid token
3. If missing/expired → call `auth.StartPreAuthFlow(ctx, oidcConfig)`
4. Print status: "Authentication valid, starting MCP server..."
5. Exit with error if pre-auth fails (configurable: retry vs exit)

**Phase 6: Device Code Fallback** (*parallel with Phase 1*)
1. Create pkg/auth/device_flow.go
2. If browser auto-open fails or `HEADLESS=true`:
   - Print to stderr: `Visit https://idp.example.com/device and enter code: ABC-123`
   - Poll token endpoint every 5s
   - Timeout after 120s with clear error

---

## Relevant Files

- main.go — Current `NewSessionHandler()` with `OnRegisterSession` hook, update to validate cached token and filter tools
- middleware.go — Current HTTP auth middleware, enhance for per-tool capability checks and re-auth on expiry
- client.go — Current `NewSessionHandler()` creates Vault client, integrate with auth token from cache
- rfc_updated_async_auth.md — Pre-auth pattern already designed, use as implementation reference
- design_concerns.txt — Lists this as blocking issue #3

**New files to create**:
- `pkg/auth/preauth_server.go` — Ephemeral HTTP callback server for OIDC flow
- `pkg/auth/token_cache.go` — Secure token persistence with expiry management
- `pkg/auth/device_flow.go` — Headless authentication fallback

---

## Verification

1. **Startup auth success**: Start server with no cached token → browser opens → authenticate → see "MCP server ready" message
2. **Cached token reuse**: Restart server within token TTL (1h) → no browser prompt → immediate MCP ready
3. **PRD compliance check**: Enable trace logs, verify `OnRegisterSession` returns only after token validation, not before
4. **Tool exposure verification**: With invalid token, attempt session init → verify session fails (no tools exposed)
5. **Expired token re-auth**: Wait for token expiry → make tool call → browser opens for re-auth → tool executes after auth
6. **Capability enforcement**: Create Vault policy with limited permissions → start session → verify only permitted tools registered
7. **Concurrent tool calls during re-auth**: Make 3 parallel tool calls when token expired → verify single browser window → all calls wait and succeed after auth
8. **Headless device flow**: Set `HEADLESS=true` → start server → verify device code printed to stderr → manual entry completes auth
9. **Port collision handling**: Start 2 servers simultaneously → verify different callback ports → both authenticate successfully

---

## Decisions

- **Pre-auth at startup (not lazy-only)**: Meets PRD "auth BEFORE session" requirement without blocking `OnRegisterSession`
- **Lazy auth as fallback**: Handles token expiration gracefully during long-running sessions
- **Cached token with OS UID**: Prevents cross-user token leakage on shared machines
- **Random callback port**: Avoids port collision when multiple servers run simultaneously
- **Device code fallback**: Supports headless environments (SSH, Docker, CI/CD)
- **Per-tool capability check**: Protects against mid-session policy changes (not just session-start check)

**Trade-off**: Extra startup step (browser prompt) vs violating PRD requirement  
**Assumption**: Users accept browser prompt at server start (documented in README)

---

## Further Considerations

1. **Startup failure behavior**: If pre-auth fails (user cancels browser), should server exit immediately or retry with configurable backoff? **Recommendation**: Exit by default, add `--auth-retry-count=3` flag for automated environments
2. **Token TTL preference**: What Vault token TTL should docs recommend? (1h = frequent re-auth, 24h = less secure) **Recommendation**: Default 1h with `TOKEN_TTL_HOURS` env var override
3. **Callback port range**: 8200-8299 conflicts with Vault default (8200). Use different range? **Recommendation**: 9200-9299 to avoid Vault conflict

---

**Next**: Please confirm this approach or clarify if you need PRD amendment to allow pure lazy auth (Option 3).


more inputs:
## Options for Auth Before MCP Session

### 1. Pre-authenticated Mode (**Recommended**)

**Flow**

```text
Start MCP Server
   ↓
Check cached Vault token
   ↓
If missing/expired → Browser OIDC login
   ↓
Get Vault token & cache locally
   ↓
Start MCP session
```

**Pros**

* ✅ Meets PRD (**auth before session**)
* ✅ No `OnRegisterSession` blocking
* ✅ Avoids MCP client timeout risk
* ✅ Best fit for **local MCP server + single client**
* ✅ Cleaner UX (reuse cached token)

**Implementation**

* Start lightweight auth server (localhost callback)
* Store Vault token locally (`~/.vault-mcp/token`)
* Re-auth only when token expires

---

### 2. Block `OnRegisterSession` (**Not Recommended**)

**Flow**

```text
VS Code/Gemini connects
   ↓
OnRegisterSession()
   ↓
Open browser login
   ↓
Wait for callback
   ↓
Create session
```

**Cons**

* ❌ Risk of MCP init timeout
* ❌ Browser popup during startup
* ❌ Fragile synchronous flow
* ❌ Poor UX if login takes time

**Use case**

* POC only

---

### 3. Authenticate on First Tool Call (**Not Recommended**)

**Flow**

```text
MCP session starts
   ↓
First tool call
   ↓
Trigger browser login
   ↓
Authenticate
   ↓
Retry tool
```

**Pros**

* ✅ Simpler implementation

**Cons**

* ❌ Violates PRD (**session exists before auth**)
* ❌ Tool behavior becomes stateful/complex

---

## Recommendation

**Choose Option 1 – Pre-authenticated Mode**

**Why**

* Local MCP server + single client (VS Code/Gemini CLI)
* Remote Vault authentication works cleanly
* `OnRegisterSession` remains lightweight
* Fully PRD compliant
* More reliable and production-friendly

### `OnRegisterSession` responsibility

Only:

```text
Validate cached token
Create Vault client
Register session
```

Avoid:

```text
Browser auth
Blocking login
Long-running sync calls
```


final plan:
Startup (Pre-Auth)
------------------
Server starts
   ↓
Check cached token
   ↓
Missing/expired?
   ├─ No → Start MCP
   └─ Yes
         Start localhost callback
         Open browser (OIDC)
         Wait ≤120s
         Exchange for Vault token
         Cache securely
         Start MCP

Session Registration
--------------------
OnRegisterSession:
   Load cached token
   Validate expiry
   Create Vault client
   Return (<100ms)

Runtime
-------
Before tool execution:
   Check token validity
   Expired?
      ├─ No → Execute tool
      └─ Yes → Re-auth
                 (single mutex)
                 Retry tool

The main thing I would challenge in review is doing remote capability checks during OnRegisterSession, because synchronous hooks should stay lightweight and not depend on remote latency.