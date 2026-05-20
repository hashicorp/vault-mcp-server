Explore vault-mcp-server codebase

Read [](file:///Users/stutisrivastava/hashicorp/ai_repo/vault-mcp-server/new_research/requirement.md)

Read [](file:///Users/stutisrivastava/hashicorp/ai_repo/vault-mcp-server/cmd/vault-mcp-server/init.go)

Read [](file:///Users/stutisrivastava/hashicorp/ai_repo/vault-mcp-server/pkg/client/client.go#1-1), lines 1 to 100

Read [](file:///Users/stutisrivastava/hashicorp/ai_repo/vault-mcp-server/cmd/vault-mcp-server/main.go#1-1), lines 1 to 150

Read [](file:///Users/stutisrivastava/hashicorp/ai_repo/vault-mcp-server/pkg/tools/tools.go)

Read [](file:///Users/stutisrivastava/hashicorp/ai_repo/vault-mcp-server/go.mod#1-1), lines 1 to 50

Read [](file:///Users/stutisrivastava/hashicorp/ai_repo/vault-mcp-server/cmd/vault-mcp-server/main.go#100-100), lines 100 to 200

Read [](file:///Users/stutisrivastava/hashicorp/ai_repo/vault-mcp-server/pkg/client/middleware.go#1-1), lines 1 to 200

Read [](file:///Users/stutisrivastava/hashicorp/ai_repo/vault-mcp-server/research_folder/auth.md)

Read [](file:///Users/stutisrivastava/hashicorp/ai_repo/vault-mcp-server/research_folder/rfc_updated_async_auth.md#1-1), lines 1 to 100

Read [](file:///Users/stutisrivastava/hashicorp/ai_repo/vault-mcp-server/research_folder/plan.md#1-1), lines 1 to 100

Read [](file:///Users/stutisrivastava/hashicorp/ai_repo/vault-mcp-server/cmd/vault-mcp-server/main.go#150-150), lines 150 to 300

Read [](file:///Users/stutisrivastava/hashicorp/ai_repo/vault-mcp-server/pkg/client/client.go#50-50), lines 50 to 188

Read [](file:///Users/stutisrivastava/hashicorp/ai_repo/vault-mcp-server/research_folder/rfc_updated_async_auth.md#50-50), lines 50 to 100

Read [](file:///Users/stutisrivastava/hashicorp/ai_repo/vault-mcp-server/e2e/e2e_test.go)

Read [](file:///Users/stutisrivastava/hashicorp/ai_repo/vault-mcp-server/cmd/vault-mcp-server/main.go#300-300), lines 300 to 350

Read [](file:///Users/stutisrivastava/hashicorp/ai_repo/vault-mcp-server/pkg/client/middleware.go#150-150), lines 150 to 150

Read [](file:///Users/stutisrivastava/hashicorp/ai_repo/vault-mcp-server/research_folder/plan.md#100-100), lines 100 to 200

Read [](file:///Users/stutisrivastava/hashicorp/ai_repo/vault-mcp-server/pkg/tools/kv/read_secret.go#1-1), lines 1 to 100

Read [](file:///Users/stutisrivastava/hashicorp/ai_repo/vault-mcp-server/research_folder/auth.md#91-91), lines 91 to 91

Read [](file:///Users/stutisrivastava/hashicorp/ai_repo/vault-mcp-server/pkg/client/ratelimit.go#1-1), lines 1 to 100

Read [](file:///Users/stutisrivastava/hashicorp/ai_repo/vault-mcp-server/pkg/client/tls.go#1-1), lines 1 to 80

Read [](file:///Users/stutisrivastava/hashicorp/ai_repo/vault-mcp-server/pkg/tools/kv/write_secret.go#1-1), lines 1 to 100

Read [](file:///Users/stutisrivastava/hashicorp/ai_repo/vault-mcp-server/README.md#1-1), lines 1 to 100

Read [](file:///Users/stutisrivastava/hashicorp/ai_repo/vault-mcp-server/Makefile#1-1), lines 1 to 80

Read [](file:///Users/stutisrivastava/Library/Application%20Support/Code/User/workspaceStorage/ac7418564c96f6dd2faa38c0dea16277/GitHub.copilot-chat/chat-session-resources/c1acb52c-b866-47ca-8e5c-9a731f610efd/toolu_016nfExUkMCwecnLhLnRedd7__vscode-1778681254397/content.txt#1-1), lines 1 to 300

Good context gathered. Now I need to grill you before designing anything — the constraint "MCP client is not in control, only mcp.json" is a critical design constraint that changes everything. 

Analyzing your answers...

Good answers. A few critical follow-ups: 

Analyzing your answers...

Now I have enough to build a comprehensive plan. Let me look at the go.mod to check existing dependencies before finalizing.  

Read [](file:///Users/stutisrivastava/hashicorp/ai_repo/vault-mcp-server/go.mod)

Read [](file:///Users/stutisrivastava/hashicorp/ai_repo/vault-mcp-server/pkg/client/client.go#1-1), lines 1 to 100

Now I have everything I need. Let me create the plan. 

Created memory file [](file:///Users/stutisrivastava/Library/Application%20Support/Code/User/workspaceStorage/ac7418564c96f6dd2faa38c0dea16277/GitHub.copilot-chat/memory-tool/memories/YzFhY2I1MmMtYjg2Ni00N2NhLThlNWMtOWE3MzFmNjEwZWZk/plan.md)

Here's the comprehensive implementation plan:

---

## Plan: OIDC Auth + Dynamic Tool Capabilities for Vault MCP Server (M1)

**TL;DR**: Add lazy OIDC authentication (Authorization Code+PKCE for local, Device Flow for remote) that triggers on the first tool call per session. A JWT from the IdP is exchanged for a Vault token via `auth/jwt`. The token is cached locally and a background renewal loop maintains it. Dynamic tool exposure filters visible tools via `sys/capabilities-self` at session start and enforces per-call. `AUTH_MODE=static` preserves existing `VAULT_TOKEN` behavior.

---

### Phase 1 — Auth Config & Package Skeleton
*All steps parallel. No dependencies.*

1. Create `pkg/auth/config.go` — parse all 18 env vars into an `AuthConfig` struct. Constants for: `AUTH_MODE`, `OIDC_DISCOVERY_URL`, `OIDC_CLIENT_ID`, `OIDC_CALLBACK_HOST` (default `127.0.0.1`), `OIDC_CALLBACK_PORT` (default `8250`), `OIDC_FLOW_MODE` (values: `browser`, `device`), `DEVICE_FLOW_ENABLED`, `VAULT_AUTH_PATH` (default `jwt`), `VAULT_AUTH_ROLE`, `TOKEN_CACHE_ENABLED` (default `true`), `TOKEN_CACHE_PATH` (default `~/.vault-mcp/token`), `TOKEN_RENEWAL_THRESHOLD_SECONDS` (default `300`), `AUTH_TIMEOUT_SECONDS` (default `120`), `AUTO_REAUTH` (default `true`), plus existing `VAULT_ADDR`, `VAULT_NAMESPACE`, `VAULT_SKIP_VERIFY`.

2. Create `pkg/auth/manager.go` — define `AuthManager` interface and `authManagerImpl` struct:
   ```
   GetOrAuthenticate(ctx) (vaultToken string, err error)
   RenewIfNeeded(ctx) error
   Invalidate()
   Close()
   ```
   `NewAuthManager(cfg AuthConfig, logger) AuthManager` — returns OIDC or static manager based on `cfg.AuthMode`.

3. Add new deps to go.mod: `golang.org/x/oauth2` and `github.com/coreos/go-oidc/v3`. `go-jose/go-jose/v4` already present.

---

### Phase 2 — Token Cache
*Independent of Phase 1. Parallel safe.*

4. Create `pkg/auth/cache.go`:
   - `TokenCache` struct with `Path string`
   - `CachedToken` JSON type: `{VaultToken, Accessor, LeaseDuration, RenewableUntil, CreatedAt, RefreshToken}`
   - `Write(t CachedToken) error` — atomic write (write temp file + rename), set `0600` perms
   - `Read() (*CachedToken, error)` — read + validate not expired
   - `Clear() error`
   - Uses `mitchellh/go-homedir` (already in go.mod) for `~` expansion

---

### Phase 3 — OIDC Authorization Code + PKCE Flow
*Depends on Phase 1.*

5. Create `pkg/auth/oidc.go`:
   - `PKCEFlow` struct with `AuthConfig` and OIDC provider (from `go-oidc/v3` discovery)
   - `Authenticate(ctx) (*TokenResult, error)`:
     1. Generate code verifier (32-byte crypto random → base64url, 43 chars min)
     2. Compute code challenge: `base64url(SHA256(verifier))`
     3. Start local `net/http` server on `OIDC_CALLBACK_HOST:OIDC_CALLBACK_PORT`
     4. Build authorization URL with `response_type=code`, `code_challenge`, `code_challenge_method=S256`, `state` (random), `redirect_uri`, `scope` (configurable, default `openid profile email`)
     5. Open browser via `exec.Command("open"/"xdg-open"/"start")`
     6. Block on channel until callback received or `AUTH_TIMEOUT_SECONDS`
     7. Validate `state` parameter in callback (CSRF protection)
     8. Exchange code → token: POST to IdP token endpoint with `grant_type=authorization_code`, `code_verifier`
     9. Verify ID token signature using OIDC provider's JWKS (via `go-oidc/v3`)
     10. Return `TokenResult{IDToken, RefreshToken, Expiry}`
   - `SilentRefresh(ctx, refreshToken) (*TokenResult, error)` — POST `grant_type=refresh_token` to IdP token endpoint

6. Create `pkg/auth/vault_exchange.go` — `ExchangeJWTForVaultToken(ctx, cfg, idToken) (vaultToken, accessor string, err error)`:
   - POST to `{VAULT_ADDR}/v1/auth/{VAULT_AUTH_PATH}/login`
   - Body: `{"jwt": idToken, "role": VAULT_AUTH_ROLE}`
   - Parse `auth.client_token`, `auth.accessor`, `auth.lease_duration`, `auth.renewable`
   - Returns Vault token

---

### Phase 4 — Device Authorization Flow
*Parallel with Phase 3. Depends on Phase 1.*

7. Create `pkg/auth/device.go`:
   - `DeviceFlow` struct with `AuthConfig`
   - `Authenticate(ctx) (*TokenResult, error)`:
     1. Discover device authorization endpoint from OIDC discovery URL
     2. POST to device authorization endpoint: `{client_id, scope}`
     3. Parse `device_code`, `user_code`, `verification_uri`, `interval`
     4. **Print to stderr** (not stdout — stdio transport uses stdout for MCP): `"Open {verification_uri} and enter code: {user_code}"`
     5. Poll token endpoint at `interval` seconds with `grant_type=urn:ietf:params:oauth:grant-type:device_code`
     6. Handle `authorization_pending`, `slow_down` errors
     7. Verify ID token, return `TokenResult`

---

### Phase 5 — Auth Manager + Token Renewal
*Depends on Phases 2, 3, 4.*

8. Implement `authManagerImpl` in `pkg/auth/manager.go`:
   - State: `currentVaultToken`, `accessor`, `tokenExpiry`, `refreshToken`, `mu sync.Mutex`
   - `GetOrAuthenticate(ctx)`:
     1. If `AUTH_MODE=static` → return `VAULT_TOKEN` env var (no-op path)
     2. If valid non-expired cached Vault token → return it
     3. If `TOKEN_CACHE_ENABLED` → try `cache.Read()` → validate against Vault `auth/token/lookup-self`
     4. Else → run `PKCEFlow` or `DeviceFlow` based on `OIDC_FLOW_MODE` → `ExchangeJWTForVaultToken` → `cache.Write()`

9. Create `pkg/auth/renewal.go` — `RenewalWorker`:
   - Background goroutine started per auth manager instance
   - Ticker at `TOKEN_RENEWAL_THRESHOLD_SECONDS` before expiry
   - Progressive recovery:
     1. POST `auth/token/renew-self` — if success, update stored token + cache
     2. If Vault renewal fails and `refreshToken != ""` → `SilentRefresh()` → `ExchangeJWTForVaultToken`
     3. If both fail and `AUTO_REAUTH=true` → trigger interactive re-auth (signals via channel)
     4. If all fail → set `authFailed=true`; next `GetOrAuthenticate` call returns error that surfaces to tool call

---

### Phase 6 — Session Integration (Lazy Auth on First Tool Call)
*Depends on Phase 5. Touches `main.go`, client.go, `middleware.go`.*

10. Modify main.go:
    - Initialize a single `AuthManager` at server startup (passed to session handlers via closure)
    - In `OnRegisterSession` hook: store `AuthManager` reference in session context (new context key `authManagerKey`)
    - In `CreateVaultClientForSession` (client.go): check `AUTH_MODE`; if `oidc`, call `authManager.GetOrAuthenticate(ctx)` (this may trigger browser/device flow on first call)

11. Modify client.go — `CreateVaultClientForSession`:
    - Add `AUTH_MODE` check
    - `static` path: existing `VAULT_TOKEN` env var behavior (unchanged)
    - `oidc` path: call `authManager.GetOrAuthenticate(ctx)` → use returned token in `NewVaultClient()`

12. Add `AuthMiddleware` in `pkg/auth/middleware.go` (or middleware.go):
    - Wraps the `server.WithToolHandlerMiddleware` chain
    - Before any tool handler: check `authManager.GetOrAuthenticate(ctx)` — if `authFailed` → return MCP error `"Authentication required. Please re-authenticate."` with instructions (device code URL or message to re-run login)
    - Ensures failed auth produces a human-readable tool result error rather than crashing
    - Order in middleware chain: `Auth → RateLimit → ToolHandler`

---

### Phase 7 — Tool Capabilities Filtering
*Depends on Phase 6. Touches `tools.go` and all individual tool files.*

13. Add capability metadata to each tool — define `ToolCapabilitySpec` in `pkg/tools/capabilities.go`:
    ```go
    type ToolCapabilitySpec struct {
        ToolName             string
        RepresentativePaths  []string  // vault paths to check
        RequiredCapabilities []string  // e.g., ["read"], ["create","update"]
    }
    ```
    Map all 16 tools to their representative Vault paths (e.g., `read_secret` → `["secret/data/+"]`, `list_secrets` → `["secret/metadata/+"]`, `list_mounts` → `["sys/mounts"]`).

14. Create `pkg/tools/capabilities.go` — `CheckAndFilterTools(ctx, vaultClient, allSpecs) ([]string, error)`:
    - Collect all representative paths from `allSpecs`
    - POST `sys/capabilities-self` with all paths
    - For each tool: check if required capabilities are in the response for its path(s)
    - Return list of authorized tool names

15. **Investigate mcp-go SDK for per-session tool registration** — check `server.ClientSession` API in v0.47.1 for `AddTool()` or `tools/list` hook:
    - **If SDK supports it**: In `OnRegisterSession`, after auth succeeds, call capability check and register only authorized tools for the session
    - **If SDK does not support per-session tool lists**: Implement a `tools/list` interceptor middleware that filters the tool list response based on a session's `authorizedTools` set stored in `activeClients` map; all tools remain registered server-wide but filtered in list + blocked per-call

16. Add per-call capability enforcement in `AuthMiddleware` (from step 12):
    - On each tool call, check if tool name is in the session's `authorizedTools` set
    - If not → return `mcp.NewToolResultError("Access denied: insufficient Vault permissions for tool X")`

---

### Phase 8 — Tests & Documentation
*Depends on all phases.*

17. Unit tests in `pkg/auth/`:
    - `cache_test.go` — write/read/expiry/clear, permissions check
    - `oidc_test.go` — PKCE code challenge generation, mock IdP callback server, state validation
    - `device_test.go` — polling logic, slow_down handling, mock device endpoint
    - `vault_exchange_test.go` — mock Vault `auth/jwt/login` response parsing
    - `renewal_test.go` — renewal trigger timing, progressive fallback logic

18. Unit tests for capability filtering in `pkg/tools/capabilities_test.go`:
    - Mock `sys/capabilities-self` responses
    - Verify correct tools filtered in/out

19. Update README.md — add `mcp.json` configuration examples:
    ```json
    {
      "mcpServers": {
        "vault": {
          "command": "vault-mcp-server",
          "args": ["stdio"],
          "env": {
            "AUTH_MODE": "oidc",
            "VAULT_ADDR": "https://vault.example.com",
            "OIDC_DISCOVERY_URL": "https://accounts.google.com",
            "OIDC_CLIENT_ID": "your-client-id",
            "VAULT_AUTH_PATH": "jwt",
            "VAULT_AUTH_ROLE": "my-role",
            "OIDC_FLOW_MODE": "browser"
          }
        }
      }
    }
    ```

---

### Relevant Files

- main.go — Add `AuthManager` init, inject into session hooks
- init.go — New auth-related cobra flags if needed
- client.go — Switch `CreateVaultClientForSession` to use `AuthManager.GetOrAuthenticate()` for `AUTH_MODE=oidc`
- middleware.go — Add `AuthMiddleware` for per-call enforcement
- tools.go — Wire in capability filtering at session start
- `pkg/auth/` *(new package)* — `config.go`, `manager.go`, `oidc.go`, `device.go`, `cache.go`, `vault_exchange.go`, `renewal.go`
- `pkg/tools/capabilities.go` *(new)* — Tool-to-path mapping, `CheckAndFilterTools()`
- go.mod — Add `golang.org/x/oauth2`, `github.com/coreos/go-oidc/v3`

---

### Verification

1. Run `go build ai_repo.` — confirm no compilation errors after all phases
2. `AUTH_MODE=static VAULT_TOKEN=<token>` — existing behavior unchanged (regression test)
3. `AUTH_MODE=oidc OIDC_FLOW_MODE=browser` — first tool call opens browser, blocks, completes auth, returns tool result
4. `AUTH_MODE=oidc OIDC_FLOW_MODE=device` — first tool call prints device code to stderr, polls, completes
5. After auth: `~/.vault-mcp/token` exists with `0600` permissions
6. Token expiry: force-expire token, verify renewal → silent refresh → interactive fallback sequence fires in order
7. Capabilities: use Vault token with read-only policy — verify write tools (`write_secret`, `delete_secret`) not exposed in `tools/list`
8. Per-call enforcement: call a filtered-out tool directly → verify `"Access denied"` MCP error returned
9. Negative: launch with `AUTH_MODE=oidc` but invalid `OIDC_DISCOVERY_URL` — verify tool call returns actionable error, session not crashed
10. Run `go test ./pkg/auth/... pkg.`

---

### Decisions

- `VAULT_AUTH_METHOD` in the env list is distinct from `VAULT_AUTH_PATH` — method refers to the protocol (`jwt`), path is the mount path (default `jwt`, could be `oidc` if Vault is configured that way). Both are configurable.
- `state` parameter (CSRF) in PKCE flow must be cryptographically random (32 bytes), validated on callback before code exchange.
- Token cache file uses atomic write (temp file + `os.Rename`) to prevent partial writes.
- Device flow prints to `stderr` only — `stdout` is the MCP JSON-RPC channel in stdio mode; writing auth prompts there would corrupt the protocol.

---

### Further Considerations

1. **Per-session tool filtering SDK constraint**: mcp-go v0.47.1 likely registers tools server-wide. The plan flags this as a Step 15 investigation. If not supported, the fallback (filter `tools/list` response + per-call block) meets the PRD's security intent but requires a deeper SDK hook. Recommend confirming this before Phase 7 begins.

2. **`VAULT_AUTH_ROLE` is missing from the env var list you provided** — Vault's `auth/jwt/login` requires a `role` parameter. Should `VAULT_AUTH_ROLE` be added to the official config list alongside `VAULT_AUTH_PATH`?

3. **OIDC scope for `groups`**: The IdP may require special configuration (e.g., Okta requires a `groups` scope claim to be added to the app). Since the server is a pass-through, the platform engineer must configure the IdP app and Vault JWT role's `groups_claim` separately — no server-side changes needed, but documentation should call this out.