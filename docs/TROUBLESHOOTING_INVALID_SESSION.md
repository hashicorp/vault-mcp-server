# Fix: "Invalid session ID" Error with MCP Server

## The Problem

You're seeing:
```
curl -X POST http://localhost:8080/mcp ...
Invalid session ID
```

Even though:
- ✅ MCP server is running
- ✅ JWT token is valid  
- ✅ Vault login works

## The Root Cause

The **MCP protocol requires session initialization** before calling any tools. You can't just call `tools/call` directly.

## When JWT Authentication Actually Happens

```
Server Startup          → No JWT auth yet (no sessions exist)
                          
Client Calls            → Session created
"initialize"            → NewSessionHandler triggered
                        → JWT token detected in environment
                        → Vault auth: vault write auth/oidc/login jwt=$TOKEN
                        → Vault token received and stored
                        → Session ready!

Client Calls            → Uses JWT-authenticated session
"tools/call"            → Works! ✅
```

## The Solution

### Quick Fix: Use the Test Script

```bash
./scripts/test-mcp-with-jwt.sh
```

This script:
1. ✅ Initializes session properly
2. ✅ Extracts session ID
3. ✅ Sends required notifications
4. ✅ Tests multiple tools
5. ✅ Shows JWT auth working

### Manual Fix: Proper curl Flow

```bash
# Step 1: Initialize session
INIT_RESPONSE=$(curl -s -i -X POST http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
      "protocolVersion": "2024-11-05",
      "clientInfo": {
        "name": "test-client",
        "version": "1.0.0"
      },
      "capabilities": {}
    }
  }')

# Step 2: Extract session ID from headers
SESSION_ID=$(echo "$INIT_RESPONSE" | grep -i "Mcp-Session-Id:" | cut -d' ' -f2 | tr -d '\r\n')
echo "Got session ID: $SESSION_ID"

# Step 3: Send initialized notification
curl -s -X POST http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -H "Mcp-Session-Id: $SESSION_ID" \
  -d '{
    "jsonrpc": "2.0",
    "method": "notifications/initialized"
  }'

# Step 4: NOW you can call tools
curl -X POST http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -H "Mcp-Session-Id: $SESSION_ID" \
  -d '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/call",
    "params": {
      "name": "list_secrets",
      "arguments": {
        "mount": "secret",
        "path": ""
      }
    }
  }'
```

**Important**: Tools require specific parameters:
- `list_secrets`: `mount` (required) + `path` (optional, defaults to "")
- `read_secret`: `mount` (required) + `path` (required)  
- `write_secret`: `mount` (required) + `path` (required) + `key` (required) + `value` (required)

## What You Should See

### At Server Startup
```
INFO Using endpoint path: /mcp
INFO Authentication is disabled           # <- This is MCP OAuth, not Vault JWT
INFO CORS Mode: strict
INFO Starting StreamableHTTP server on 127.0.0.1:8080/mcp
```

**Note**: "Authentication is disabled" refers to MCP's OAuth authentication middleware, NOT Vault JWT authentication!

### When Client Initializes Session
```
INFO HTTP request received  method=POST path=/mcp
DEBU Vault address configured via request context
INFO Using JWT authentication for Vault  session_id=abc-123
DEBU Authenticating with Vault using JWT  auth_path=auth/oidc/login role=mcp-role
INFO Successfully authenticated to Vault using JWT  
     session_id=abc-123 token_ttl=3600 policies=[vault-policy-admin]
INFO Created Vault client with JWT authentication
```

## Verification

Run this to confirm everything is working:

```bash
# Terminal 1: Server (if not already running)
source /tmp/vault-jwt-env.sh
./bin/vault-mcp-server streamable-http

# Terminal 2: Test
./scripts/test-mcp-with-jwt.sh
```

You should see:
```
✅ MCP server is running
✅ Session initialized: <session-id>
✅ Available tools: list_secrets, write_secret, read_secret, ...
✅ list_secrets call succeeded!
✅ Secret written successfully!
✅ Secret read successfully!
```

## Why This Design?

1. **Multi-tenant**: Each MCP client gets its own session with its own JWT token
2. **Security**: JWT tokens are never exposed in URLs or logs
3. **Audit**: Each session is tied to a specific user (from JWT claims)
4. **Scalability**: Sessions can be managed independently

## Summary

❌ **Don't do this**:
```bash
curl http://localhost:8080/mcp -d '{"method":"tools/call",...}'
# Result: Invalid session ID
```

✅ **Do this**:
```bash
# 1. Initialize session → JWT auth happens here
curl http://localhost:8080/mcp -d '{"method":"initialize",...}'

# 2. Use session ID for all subsequent calls
curl -H "Mcp-Session-Id: $SESSION_ID" http://localhost:8080/mcp -d '{"method":"tools/call",...}'
```

✅ **Or just use the test script**:
```bash
./scripts/test-mcp-with-jwt.sh
```

## Further Reading

- [Complete JWT Auth Guide](./COMPLETE_JWT_AUTH_GUIDE.md) - Full documentation
- [MCP Protocol Specification](https://spec.modelcontextprotocol.io/) - Official MCP docs
- [Session Management Code](../pkg/client/client.go) - How sessions work
