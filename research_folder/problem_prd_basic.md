Core Problem

1. Identity & Access Management: Current reliance on static tokens is insecure
2. Agent Traceability: Lack of audit trails for agent actions
3. Guided Usage: No framework for secure usage patterns
4. Scalability: Need for multi-tenant isolation

1.  Weak Authentication (Biggest Issue)
    • Uses static tokens 
    • Agents may get more access than intended 
    • No guarantee actions are tied to a real user 
👉 Risk: Agent can act like an admin unintentionally

2. No Proper Access Control
    • MCP exposes too many tools blindly 
    • Agents can attempt actions they shouldn’t 
👉 Risk: Unauthorized operations

3. No Traceability
    • Hard to answer: 
        ○ Who triggered this? 
        ○ Was it the user or the agent? 
        ○ What exactly happened? 
👉 Risk: No audit trail → compliance issues

4. No Guidance (Too Generic)
    • MCP behaves like raw API access 
    • No “safe patterns” or recommended workflows 
👉 Risk: Misuse of Vault

5. Not Enterprise-Ready
    • No scalability 
    • No isolation between users/agents 

Architecture Flow:  




M1 Requirement: 
    
    1. OIDC-Based Authentication	Purpose: Replace static tokens with dynamic, user-scoped authentication. Instead of tokens → use SSO login (Okta, Azure AD, etc.)
        Key idea:
                Agent = acting on behalf of a real user
        ✔ Agent inherits exact user permissions
        ✔ No privilege escalation
        ✔ Fully traceable identity
        Implementation:
        • Integrate with enterprise IdPs (Okta, Azure AD, Ping)
        • Agent inherits exact user permissions (no privilege escalation)
        • Session-based authentication tied to human identity
                
    Scope & Namespace-Based Governance (Pre-Tool Filtering)  (Fix Authorization)	Instead of: Agent sees all tools → tries → gets denied  (Purpose: Prevent unauthorized actions before they're attempted)
        New approach: Agent never sees restricted tools at all 
        How it works:
                
                • Extract user permissions from JWT 
                • Check: 
                        ○ Namespace access 
                        ○ Policy capabilities 
                • Remove unauthorized tools from response 
        Result:
                Agent literally cannot attempt forbidden actions
                Example: If user lacks delete capability on sys/mounts, the tool for deleting secret engines won't appear in the agent's available tools list.
    Safety By Default (Sensitive Operation Gating) (Fix Risky Operations)	Purpose: Require explicit approval for dangerous operations
        Sensitive Operations Include:
        • Create/Update/Delete actions
        • Enabling public auth methods
        • Deleting secret engines
        Default behaviour: Disabled
        If enabled: Requires Human-in-the-Loop (HITL)
        Flow:
                1. Agent requests action 
                2. System pauses 
                3. User gets confirmation prompt 
                4. Action executes only if approved
        Flow:
        1. Default: All sensitive operations disabled
        2. Opt-in: Set VAULT_MCP_ENABLE_SENSITIVE_OPERATIONS=true
        3. Execution: Even when enabled, requires Human-in-the-Loop (HITL) approval unless VAULT_MCP_ALLOW_AUTO_APPROVAL is set
        
    Traceability & Logging (Fix Observability)	Two-Layer Approach:
        Layer 1 - Vault Audit (Compliance):
        • Uses X-Vault-Audit-Data headers
        • Every request includes human user's OIDC identity
        • Creates authoritative audit trail
        Layer 2 - MCP Server Logs (Observability):
        • Structured logs for all JSON-RPC requests
        • Includes Subject claim from JWT
        • Enables debugging and monitoring of blocked attempts
                • Logs: 
                        ○ Agent request 
                        ○ User identity (JWT subject) 
                        ○ Intended action 
                Helps debug:
                        ○ Why something failed 
                        ○ What agent attempted
        
        
        
        
        
    
    
    
    Feasibility of PRD Requirements
    Requirement	Verdict	Key Finding
    OIDC Authentication	Feasible with caveats	mcp-go v0.47.1 has OAuth 2.0 client-side support, but server-side JWT validation must be custom-built. Vault's JWT auth method can bridge OIDC→Vault token, but the PRD doesn't call out this prerequisite.
    Pre-Tool Filtering	Feasible but complex	mcp-go does NOT natively support per-session dynamic tool filtering. Current code statically registers all 16 tools in tools.go. A custom middleware intercepting tools/list is needed. Also, filtering alone is insufficient — execution-time enforcement is also required since a client could call a hidden tool directly.
    Sensitive Operation Gating	Best-supported requirement	mcp-go has full Sampling support (EnableSampling() + RequestSampling()). Tool annotations (DestructiveHint, ReadOnlyHint) already exist in tool metadata but are not enforced. Adding VAULT_MCP_ENABLE_SENSITIVE_OPERATIONS env var and HITL confirmation is architecturally clean.
    Traceability & Logging	Feasible, large gaps to fill	Logrus framework in place, but: no X-Vault-Audit-Data header propagation, no JSON-RPC request logging, no user identity in logs, no tool invocation audit trail, no request correlation IDs. See middleware.go — HTTP request logging exists but is shallow.
    
    
    Concerns : 
1. “We might be assuming things that aren’t actually supported”
worried that the current idea assumes:
    • The system will accept certain scope formats 
    • The authorization server supports specific features (like token exchange, special endpoints) 
    But in reality, not all auth servers support these.
Simple version:
    “We might be building a solution that only works in ideal conditions, not in real customer setups.”

2. “We’re jumping into design too early”
explicitly says this needs a proper investigation before designing.
    Meaning:
    • There are still unknowns 
    • Edge cases and limitations are not fully understood 
Simple version:
    “Let’s not design the architecture yet—we don’t fully understand the problem space.”

3. “Policy and scope mapping might not be straightforward”
    “respect jwt claims of the scope type as valid policy names”
This suggests concern that:
    • You’re treating OAuth scopes like Vault policies 
    • But those may not map cleanly or correctly 
Simple version:
    “We might be incorrectly equating scopes with policies, which could break security or logic.”

4. Underlying concern (the real signal)
    is basically saying:
    “This looks promising, but it’s risky to proceed without validating assumptions—especially around compatibility and security.”

