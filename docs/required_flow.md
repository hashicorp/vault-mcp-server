MCP server running

VS Code (client agnostic)
   ↓
Local MCP Server
   ↓ opens browser
IdP login
   ↓ callback
Local MCP Server stores token
  ↓ token exchange - get JWT token
Vault login using JWT token from MCP server 
  ↓ 
get Vault token
  ↓ 
Access vault MCP server and access tools



┌─────────────────────────┐
│ VS Code / Gemini CLI    │
│ (MCP Client)            │
└────────────┬────────────┘
             │ MCP connect
             │
┌────────────▼────────────┐
│ Local Vault MCP Server  │
│                         │
│ Startup:                │
│ check cached token      │
│        │                │
│   valid?                │
│    ├── yes → start MCP  │
│    └── no               │
│         browser login   │
│         OIDC flow       │
│         cache token     │
│         start MCP       │
└────────────┬────────────┘
             │
             │ Vault token
             │
┌────────────▼────────────┐
│ Remote Vault Server     │
└─────────────────────────┘

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
