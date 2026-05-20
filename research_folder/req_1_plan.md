I'll help you create a comprehensive plan for implementing OIDC-based authentication for the Vault MCP Server. Let me start by exploring the codebase to understand the current architecture. 

## Plan: OIDC Authentication for Vault MCP Server (Requirement 1)

Implement OIDC-based authentication enabling users to authenticate with enterprise identity, exchange JWT tokens for Vault tokens, and access only authorized tools with full audit traceability.

**Approach**: Incremental delivery in 3 phases — Core OIDC auth, Policy-based tool filtering, Token refresh + HITL approval.

---

### Phase 1: Core OIDC Authentication & JWT Exchange

**Goal**: Enable OIDC browser flow → JWT → Vault token → authenticated MCP session

**Steps**
1. Create OIDC config module (`pkg/auth/oidc_config.go`) — load issuer, client ID, secret, scopes from env vars
2. Implement OIDC auth flow (`pkg/auth/oidc_client.go`) — use `golang.org/x/oauth2`, PKCE, browser launch, token validation (*depends on 1*)
3. Implement OAuth callback server (`pkg/auth/callback_server.go`) — reuse MCP HTTP server `/auth/callback` when available, ephemeral for stdio (*depends on 2*)
4. Implement JWT→Vault token exchange (`pkg/auth/vault_jwt_exchange.go`) — call Vault's JWT auth endpoint, create authenticated client (*depends on 2*)
5. Validate JWT auth method on startup (`pkg/auth/vault_jwt_validation.go`) — check `/sys/auth/{jwt_mount}` exists (*depends on 4*)
6. Integrate OIDC into session init — modify client.go `NewSessionHandler()`, OIDC first → fallback to static token (*depends on 1-5*)
7. Store user identity in session — extend session storage with JWT claims, subject, email (*depends on 6*)
8. Enhance audit logging — modify middleware.go + all tool handlers to log JWT claims + user identity + tool + params + result (*depends on 7*)
9. Update server initialization — modify main.go to load OIDC config, validate JWT auth, register callback endpoint (*depends on 1-8*)
10. Documentation — update README.md with OIDC env vars, setup guide, provider examples (*parallel with 1-9*)

**Verification**
1. Stdio mode OIDC auth → browser launches, session established with JWT-derived token
2. HTTP mode OIDC auth → `/auth/callback` receives code, session established
3. Static token fallback → no OIDC config, uses `VAULT_TOKEN` (backward compat)
4. Invalid OIDC config → session fails with clear error
5. JWT auth not enabled → startup validation fails with setup instructions
6. Failed OIDC exchange → session rejected
7. Audit logs contain JWT subject, email, claims, tool names, parameters
8. Concurrent session rejected (single session mode)

---

### Phase 2: Policy-Based Dynamic Tool Filtering

**Goal**: Query user permissions, expose only authorized tools (category + tool-level filtering)

**Steps**
1. Create policy evaluator (`pkg/auth/policy_evaluator.go`) — query token metadata, extract policies (*depends on Phase 1*)
2. Implement capability checking — call `sys/capabilities-self` for paths, cache results (*depends on 1*)
3. Define tool-to-path mapping (`pkg/auth/tool_permissions.go`) — map 21 tools to required paths + capabilities (*depends on 2*)
4. Evaluate permissions at session start — modify client.go `NewSessionHandler()`, store results in session (*depends on 2-3*)
5. Implement dynamic tool registration — modify tools.go to register only authorized tools (*depends on 4*)
6. Add discovery endpoint — ensure `tools/list` reflects accessible tools only (*parallel with 5*)
7. Handle authorization errors — tool handlers catch Vault 403, return user-friendly errors (*depends on 4-5*)

**Verification**
1. Admin user → all 21 tools exposed
2. KV-only policy → only KV tools (no PKI/Sys)
3. Read-only policy → write/delete tools hidden
4. No PKI mount access → PKI category hidden
5. Path-level restriction → tool available but runtime Vault deny
6. `tools/list` matches permissions
7. Unauthorized op → audit log shows denial + user identity

---

### Phase 3: Proactive Token Refresh & HITL Approval

**Goal**: Auto-refresh tokens before expiry, require approval for write/delete operations

**Steps**
1. Implement TTL monitoring (`pkg/auth/token_refresh.go`) — background goroutine, trigger at 80% TTL (*depends on Phase 1*)
2. Implement OIDC refresh flow — modify pkg/auth/oidc_client.go `RefreshJWT()` using refresh token (*depends on 1*)
3. Implement Vault token renewal — exchange new JWT for fresh Vault token (*depends on 1-2*)
4. Integrate refresh into session — modify client.go, start monitoring after auth, update client on refresh (*depends on 1-3*)
5. Define write operation tools (`pkg/auth/tool_classification.go`) — classify tools: read-only vs write vs delete (*no deps*)
6. Implement approval prompt (`pkg/auth/approval.go`) — stdin prompt for stdio, MCP sampling for HTTP, 30s timeout (*depends on 5*)
7. Create approval middleware (`pkg/client/approval_middleware.go`) — check classification, request approval pre-execution (*depends on 6*)
8. Integrate middleware — modify tools.go to wrap write handlers with approval (*depends on 7*)
9. Add approval audit logging — log approval requests + decisions + user identity (*depends on 7-8*)
10. Documentation — update README.md with refresh/approval config, UX guide (*parallel with 1-9*)

**Verification**
1. Token refresh → wait for threshold, verify auto-refresh, no disruption
2. Write approval granted → `write_secret` with approval → secret written
3. Delete approval granted → `delete_secret` with approval → secret deleted
4. Write approval denied → operation canceled, Vault not called
5. Approval timeout → no response → timeout error after 30s
6. Refresh failure → session terminated gracefully
7. Approved op audit → log shows approval grant + success
8. Denied op audit → log shows denial, no Vault call
9. Read-only bypass → `read_secret` no approval prompt
10. Admin bypass → `VAULT_ENABLE_APPROVAL=false` → no prompts

---

### Relevant Files

**New files** (pkg/auth package — all new):
- `oidc_config.go`, `oidc_client.go`, `callback_server.go`, `vault_jwt_exchange.go`, `vault_jwt_validation.go` — Phase 1 OIDC auth
- `policy_evaluator.go`, `tool_permissions.go` — Phase 2 policy filtering
- `token_refresh.go`, `tool_classification.go`, `approval.go` — Phase 3 refresh + HITL
- `approval_middleware.go` (in pkg/client) — approval wrapper

**Modified files**:
- main.go — OIDC init, callback endpoint, JWT auth validation
- init.go — OIDC env vars
- client.go — OIDC session flow, user identity storage, token refresh
- middleware.go — audit logging enhancements
- tools.go — dynamic registration, approval middleware
- All tool handlers in kv, pki, sys — user identity logging
- README.md — OIDC config docs

**Dependencies**: `golang.org/x/oauth2`, `github.com/coreos/go-oidc/v3/oidc`

---

### Decisions

- **OIDC Config**: Generic params via env vars (`VAULT_OIDC_ISSUER`, `VAULT_OIDC_CLIENT_ID`, etc.), works with any provider
- **Auth Flow**: Browser-based OAuth code flow with PKCE, callback server reuses HTTP endpoint when available
- **Transport Support**: Both stdio and HTTP modes
- **Token Exchange**: MCP server exchanges JWT → Vault token
- **JWT Auth Mount**: Configurable, defaults to `/auth/jwt`, validated on startup
- **Backward Compat**: Coexist with static token (OIDC precedence, fall back to `VAULT_TOKEN`)
- **Session Binding**: 1:1:1 Session-OIDC-Token, single session only (local mode)
- **Policy Filtering**: Category-level + selective tool-level + runtime Vault authz
- **Token Refresh**: Automatic proactive at 80% TTL, uses OIDC refresh token
- **Write Gating**: HITL approval required for write/delete/create ops, 30s timeout
- **Audit Logging**: All non-sensitive JWT claims + tool + params + result + approval decision
- **Error Messages**: Dual-level (detailed logs + user-friendly MCP responses)

---

### Further Considerations

1. **JWT Auth Role Config**: Assume admin configures role correctly, validate existence only, provide best-practice docs
2. **Multi-Namespace**: Phase 1 single namespace, add multi-namespace in future if needed
3. **OIDC Scopes**: Default `openid profile email offline_access`, override via env var
4. **Refresh Token**: Include `offline_access` scope for Phase 3 (document provider approval requirements)
5. **OAuth State Security**: Cryptographic random 32-byte state, 5min timeout, validate on callback
6. **Approval Caching**: Phase 3 requires per-op approval, consider session-level caching in future based on feedback
7. **Audit Destination**: Phase 1 stdout/stderr JSON, future: audit file + syslog support
8. **Token Revocation**: No auto-revocation in Phase 1-3 (TTL-based expiry sufficient), consider for future

---

The plan is persisted to /memories/session/plan.md. Ready for your review and approval or further refinement!