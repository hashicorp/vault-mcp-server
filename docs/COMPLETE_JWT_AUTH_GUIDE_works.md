# Complete JWT Authentication Guide for Vault MCP Server

## Overview

This guide demonstrates how to authenticate to Vault using JWT/access tokens from an OIDC provider (like Okta) and use the MCP server to impersonate as a user/agent.

## Authentication Flow

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐     ┌────────────┐
│             │     │              │     │             │     │            │
│  MCP Client │────▶│ OIDC Provider│────▶│ MCP Server  │────▶│   Vault    │
│             │     │   (Okta)     │     │             │     │            │
└─────────────┘     └──────────────┘     └─────────────┘     └────────────┘
      │                    │                     │                   │
      │  1. User Login     │                     │                   │
      │───────────────────▶│                     │                   │
      │                    │                     │                   │
      │  2. JWT Token      │                     │                   │
      │◀───────────────────│                     │                   │
      │                    │                     │                   │
      │  3. Call MCP Tools │                     │                   │
      │────────────────────┼────────────────────▶│                   │
      │                    │                     │                   │
      │                    │                     │  4. Auth w/ JWT   │
      │                    │                     │──────────────────▶│
      │                    │                     │                   │
      │                    │                     │  5. Vault Token   │
      │                    │                     │◀──────────────────│
      │                    │                     │                   │
      │                    │                     │  6. API Calls     │
      │                    │                     │◀─────────────────▶│
      │                    │                     │                   │
      │  7. Response       │                     │                   │
      │◀───────────────────┴─────────────────────│                   │
```

## Prerequisites

- Vault running at `http://127.0.0.1:8200`
- Vault root token or admin access
- Okta/Auth0 or other OIDC provider configured
- MCP server binary built (`./bin/vault-mcp-server`)

## Step 1: Configure Vault for JWT Authentication

### Option A: Automated Setup (Recommended)

```bash
# Run the setup script
./scripts/setup-vault-jwt-auth.sh
```

### Option B: Manual Setup

```bash
# Set Vault address
export VAULT_ADDR='http://127.0.0.1:8200'

# Login to Vault (if needed)
vault login

# Enable OIDC auth method (if not already enabled)
vault auth enable oidc

# Configure OIDC auth method with your Okta/OIDC provider
vault write auth/oidc/config \
    oidc_discovery_url="https://your-domain.okta.com/oauth2/default" \
    oidc_client_id="your-client-id" \
    default_role="mcp-role"

# Create a JWT role with appropriate policies
vault write auth/oidc/role/mcp-role \
    role_type="jwt" \
    bound_audiences="api://default" \
    user_claim="sub" \
    policies="vault-policy-admin" \
    token_ttl=1h \
    token_max_ttl=4h \
    oidc_scopes="openid,profile,email"

# Verify configuration
vault read auth/oidc/config
vault read auth/oidc/role/mcp-role
```

## Step 2: Obtain JWT Token from OIDC Provider

### Option A: Automated (Recommended)

```bash
# This script handles the entire PKCE flow and obtains the JWT token
./scripts/get-jwt-and-run-mcp.sh
```

This will:
1. Generate PKCE codes
2. Open your browser for authentication
3. Exchange authorization code for access token
4. Test Vault authentication
5. Save environment variables
6. Optionally start the MCP server

### Option B: Manual PKCE Flow

```bash
# 1. Generate PKCE codes
CODE_VERIFIER=$(openssl rand -hex 32)
CODE_CHALLENGE=$(printf '%s' "$CODE_VERIFIER" \
  | openssl dgst -binary -sha256 \
  | openssl base64 -A \
  | tr '+/' '-_' \
  | tr -d '=')

# 2. Build authorization URL (adjust for your provider)
AUTH_URL="https://your-domain.okta.com/oauth2/default/v1/authorize"
AUTH_URL="${AUTH_URL}?client_id=your-client-id"
AUTH_URL="${AUTH_URL}&response_type=code"
AUTH_URL="${AUTH_URL}&scope=openid%20profile%20email"
AUTH_URL="${AUTH_URL}&redirect_uri=http://localhost:3000/callback"
AUTH_URL="${AUTH_URL}&state=random_state_string"
AUTH_URL="${AUTH_URL}&code_challenge=${CODE_CHALLENGE}"
AUTH_URL="${AUTH_URL}&code_challenge_method=S256"

# 3. Open the URL in browser
open "$AUTH_URL"

# 4. After authentication, copy the redirect URL
# Example: http://localhost:3000/callback?code=xyz123&state=random_state_string

# 5. Extract authorization code
read -p "Paste redirect URL: " REDIRECT_URL
AUTH_CODE=$(echo "$REDIRECT_URL" | sed -n 's/.*code=\([^&]*\).*/\1/p')

# 6. Exchange code for access token
curl --request POST \
  --url "https://your-domain.okta.com/oauth2/default/v1/token" \
  --header 'content-type: application/x-www-form-urlencoded' \
  --data "grant_type=authorization_code" \
  --data "client_id=your-client-id" \
  --data "redirect_uri=http://localhost:3000/callback" \
  --data "code=${AUTH_CODE}" \
  --data "code_verifier=${CODE_VERIFIER}"

# 7. Extract access_token from the JSON response
```

## Step 3: Configure MCP Server with JWT Token

### Set Environment Variables

```bash
# Vault configuration
export VAULT_ADDR='http://127.0.0.1:8200'

# JWT authentication (REQUIRED)
export VAULT_JWT_TOKEN='your-access-token-from-step-2'
export VAULT_JWT_ROLE='mcp-role'
export VAULT_JWT_AUTH_PATH='oidc'

# Optional: Vault namespace (Enterprise only)
# export VAULT_NAMESPACE='my-namespace'
```

### Test Vault Authentication

```bash
# Test that JWT authentication works
vault write auth/oidc/login \
    role="$VAULT_JWT_ROLE" \
    jwt="$VAULT_JWT_TOKEN"
```

Expected output:
```
Key                  Value
---                  -----
token                hvs.CAESIJ...
token_accessor       ...
token_duration       1h
token_renewable      true
token_policies       ["default" "vault-policy-admin"]
```

## Step 4: Start MCP Server

```bash
# Start the server (it will automatically use JWT authentication)
./bin/vault-mcp-server streamable-http
```

Expected log output at startup:
```
INFO Using endpoint path: /mcp
INFO Authentication is disabled  # This refers to MCP OAuth auth, NOT Vault JWT auth
INFO CORS Mode: strict
INFO Starting StreamableHTTP server on 127.0.0.1:8080/mcp
```

**Important**: JWT authentication to Vault happens **when a client creates a session**, not at server startup. You'll see these logs when a client connects:

```
INFO HTTP request received  method=POST path=/mcp
DEBU Vault address configured via request context
INFO Using JWT authentication for Vault  session_id=<id>
DEBU Authenticating with Vault using JWT
INFO Successfully authenticated to Vault using JWT  session_id=<id>
INFO Created Vault client with JWT authentication
```

## Step 5: Test MCP Server

### Automated Test (Recommended)

Use the automated test script that properly handles MCP session initialization:

```bash
# Run the complete test suite
./scripts/test-mcp-with-jwt.sh
```

This script will:
1. Initialize an MCP session (required!)
2. Get a session ID from the server
3. Test various MCP tools (list_secrets, write_secret, read_secret, list_mounts)
4. Show how JWT authentication works behind the scenes

### Manual Test with curl

**Important**: The MCP protocol requires session initialization before calling tools.

#### Step 1: Initialize Session

```bash
# Initialize MCP session and capture session ID
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

# Extract session ID from response headers
SESSION_ID=$(echo "$INIT_RESPONSE" | grep -i "Mcp-Session-Id:" | cut -d' ' -f2 | tr -d '\r\n')
echo "Session ID: $SESSION_ID"

# Send initialized notification (required)
curl -s -X POST http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -H "Mcp-Session-Id: $SESSION_ID" \
  -d '{
    "jsonrpc": "2.0",
    "method": "notifications/initialized"
  }'
```

**At this point**, the MCP server:
- Creates a session with the session ID
- Calls `NewSessionHandler` which triggers JWT authentication
- Authenticates to Vault using your JWT token
- Stores the Vault client for this session

#### Step 2: List Secrets

```bash
# List secrets at the root of the 'secret' mount
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

# List secrets under a specific path
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
        "path": "myapp"
      }
    }
  }'
```

#### Step 3: Write a Secret

```bash
# Write a secret (key/value pair)
curl -X POST http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -H "Mcp-Session-Id: $SESSION_ID" \
  -d '{
    "jsonrpc": "2.0",
    "id": 3,
    "method": "tools/call",
    "params": {
      "name": "write_secret",
      "arguments": {
        "mount": "secret",
        "path": "myapp/config",
        "key": "password",
        "value": "secret123"
      }
    }
  }'
```

**Note**: `write_secret` takes individual `key` and `value` parameters, not a `data` object.

#### Step 4: Read the Secret

```bash
curl -X POST http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -H "Mcp-Session-Id: $SESSION_ID" \
  -d '{
    "jsonrpc": "2.0",
    "id": 4,
    "method": "tools/call",
    "params": {
      "name": "read_secret",
      "arguments": {
        "mount": "secret",
        "path": "myapp/config"
      }
    }
  }'
```

**Parameter Explanation**:
- `mount`: The KV secret engine mount point (e.g., "secret", "kv")  
- `path`: The path within that mount (e.g., "myapp/config")
- For `write_secret`: `key` and `value` for the secret data

Example: To access `secret/myapp/config`:
- `mount`: "secret"
- `path`: "myapp/config"
```

### Common Error: "Invalid session ID"

If you get this error, it means you tried to call a tool without initializing a session first. Always:
1. Call `initialize` method first
2. Extract the `Mcp-Session-Id` from response headers
3. Include that session ID in all subsequent requests

## How It Works

### 1. JWT Authentication Priority

The MCP server checks for authentication in this order:

```go
// From pkg/client/client.go:CreateVaultClientForSession

// 1. Check for JWT token
jwtToken := getEnv(VaultJWTToken, "")
if jwtToken != "" {
    // Use JWT authentication
    NewVaultClientWithJWT(...)
}

// 2. Fall back to direct Vault token
vaultToken := getEnv(VaultToken, "")
if vaultToken != "" {
    // Use token authentication
    NewVaultClient(...)
}
```

### 2. JWT to Vault Token Exchange

When JWT token is provided:

```go
// From pkg/client/client.go:NewVaultClientWithJWT

// Authenticate using JWT
authPath := fmt.Sprintf("auth/%s/login", jwtAuthPath)
data := map[string]interface{}{
    "role": jwtRole,
    "jwt":  jwtToken,
}

secret, err := client.Logical().Write(authPath, data)

// Extract Vault token from response
vaultToken := secret.Auth.ClientToken
client.SetToken(vaultToken)
```

### 3. User Impersonation

The JWT token contains claims (sub, email, etc.) that Vault uses to:
- Validate the user's identity
- Apply appropriate policies based on the role
- Issue a Vault token with user-specific permissions
- Enable audit logging with user context

## Complete Example Configuration Files

### Example 1: JWT Authentication Only

Create `.env.jwt` file:
```bash
# Vault server
export VAULT_ADDR='http://127.0.0.1:8200'

# JWT authentication
export VAULT_JWT_TOKEN='eyJraWQiOiJpa0xMd2pYSGd4b0t...'
export VAULT_JWT_ROLE='mcp-role'
export VAULT_JWT_AUTH_PATH='oidc'

# MCP server
export TRANSPORT_MODE='streamable-http'
export TRANSPORT_HOST='127.0.0.1'
export TRANSPORT_PORT='8080'
export MCP_ENDPOINT='/mcp'
```

Usage:
```bash
source .env.jwt
./bin/vault-mcp-server streamable-http
```

### Example 2: MCP Client Configuration

For Claude Desktop or other MCP clients:

```json
{
  "mcpServers": {
    "vault": {
      "command": "/path/to/vault-mcp-server",
      "args": ["streamable-http"],
      "env": {
        "VAULT_ADDR": "http://127.0.0.1:8200",
        "VAULT_JWT_TOKEN": "your-jwt-token",
        "VAULT_JWT_ROLE": "mcp-role",
        "VAULT_JWT_AUTH_PATH": "oidc"
      }
    }
  }
}
```

## Troubleshooting

### Error: "Invalid session ID"

**Cause**: Attempting to call MCP tools without initializing a session first

**Solution**:
The MCP protocol requires session initialization before calling any tools. This is when JWT authentication actually happens.

```bash
# ❌ WRONG - This will fail with "Invalid session ID"
curl -X POST http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "method": "tools/call", ...}'

# ✅ CORRECT - Initialize session first
# 1. Initialize session
INIT_RESPONSE=$(curl -s -i -X POST http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
      "protocolVersion": "2024-11-05",
      "clientInfo": {"name": "test", "version": "1.0"}
    }
  }')

# 2. Extract session ID
SESSION_ID=$(echo "$INIT_RESPONSE" | grep -i "Mcp-Session-Id:" | cut -d' ' -f2 | tr -d '\r\n')

# 3. Send initialized notification
curl -X POST http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -H "Mcp-Session-Id: $SESSION_ID" \
  -d '{"jsonrpc": "2.0", "method": "notifications/initialized"}'

# 4. Now you can call tools
curl -X POST http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -H "Mcp-Session-Id: $SESSION_ID" \
  -d '{"jsonrpc": "2.0", "method": "tools/call", ...}'
```

**Or use the automated test script**:
```bash
./scripts/test-mcp-with-jwt.sh
```

### Error: "JWT authentication failed"

**Cause**: Invalid JWT token or misconfigured Vault role

**Solution**:
```bash
# 1. Verify JWT token is valid
echo $VAULT_JWT_TOKEN

# 2. Check Vault role configuration
vault read auth/oidc/role/mcp-role

# 3. Test authentication manually
vault write auth/oidc/login role=mcp-role jwt=$VAULT_JWT_TOKEN

# 4. Check Vault logs
vault audit list
```

### Error: "no authentication data returned from Vault"

**Cause**: JWT token doesn't match bound_audiences or other constraints

**Solution**:
```bash
# Check JWT token claims
# Decode JWT at https://jwt.io or using:
echo $VAULT_JWT_TOKEN | cut -d. -f2 | base64 -d

# Verify bound_audiences matches the "aud" claim in JWT
vault read auth/oidc/role/mcp-role

# Update role if needed
vault write auth/oidc/role/mcp-role \
    role_type="jwt" \
    bound_audiences="correct-audience" \
    user_claim="sub" \
    policies="vault-policy-admin"
```

### Error: "vault token or JWT token not provided for session"

**Cause**: Environment variable not set

**Solution**:
```bash
# Verify environment variables
echo "VAULT_ADDR: $VAULT_ADDR"
echo "VAULT_JWT_TOKEN: ${VAULT_JWT_TOKEN:0:20}..."
echo "VAULT_JWT_ROLE: $VAULT_JWT_ROLE"
echo "VAULT_JWT_AUTH_PATH: $VAULT_JWT_AUTH_PATH"

# Source the environment file
source /tmp/vault-jwt-env.sh
```

### JWT Token Expired

**Cause**: Access tokens typically expire after 1 hour

**Solution**:
```bash
# Option 1: Re-run the automated script
./scripts/get-jwt-and-run-mcp.sh

# Option 2: Implement token refresh in your application
# Use refresh_token to get a new access_token
curl --request POST \
  --url "https://your-domain.okta.com/oauth2/default/v1/token" \
  --header 'content-type: application/x-www-form-urlencoded' \
  --data "grant_type=refresh_token" \
  --data "client_id=your-client-id" \
  --data "refresh_token=$REFRESH_TOKEN"
```

## Security Best Practices

1. **Never commit JWT tokens to git**
   - Add `*.env` and `*env.sh` to `.gitignore`
   - Use secret management tools in production

2. **Use TLS in production**
   ```bash
   export MCP_TLS_CERT_FILE="/path/to/cert.pem"
   export MCP_TLS_KEY_FILE="/path/to/key.pem"
   ```

3. **Rotate JWT tokens regularly**
   - Implement token refresh logic
   - Set appropriate token TTLs in Vault

4. **Use least privilege policies**
   ```bash
   # Create restricted policy
   vault policy write mcp-limited - <<EOF
   path "secret/data/myapp/*" {
     capabilities = ["read", "list"]
   }
   EOF
   
   # Update role to use restricted policy
   vault write auth/oidc/role/mcp-role \
       policies="mcp-limited"
   ```

5. **Enable audit logging**
   ```bash
   vault audit enable file file_path=/var/log/vault/audit.log
   ```

## Advanced: Dynamic JWT Token Refresh

For long-running MCP servers, implement token refresh:

```bash
#!/bin/bash
# refresh-jwt-token.sh

REFRESH_TOKEN="your-refresh-token"
CLIENT_ID="your-client-id"
TOKEN_URL="https://your-domain.okta.com/oauth2/default/v1/token"

# Get new access token
RESPONSE=$(curl --silent --request POST \
  --url "$TOKEN_URL" \
  --header 'content-type: application/x-www-form-urlencoded' \
  --data "grant_type=refresh_token" \
  --data "client_id=$CLIENT_ID" \
  --data "refresh_token=$REFRESH_TOKEN")

# Extract new token
NEW_TOKEN=$(echo "$RESPONSE" | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)

# Update environment
export VAULT_JWT_TOKEN="$NEW_TOKEN"

# Signal MCP server to reload (if implemented)
# pkill -USR1 vault-mcp-server
```

## References

- [JWT Authentication Documentation](./JWT_IMPLEMENTATION_SUMMARY.md)
- [JWT Quick Reference](./JWT_QUICK_REFERENCE.md)
- [OIDC Setup Guide](./OKTA_SETUP.md)
- [Vault JWT Auth Method](https://www.vaultproject.io/docs/auth/jwt)
- [PKCE Flow (RFC 7636)](https://tools.ietf.org/html/rfc7636)
