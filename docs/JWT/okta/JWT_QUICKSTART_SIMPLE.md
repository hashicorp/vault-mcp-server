# 🚀 Quick Start: JWT Authentication with Vault MCP Server

Your Vault MCP Server is **already configured** with JWT authentication support! Here's how to use it:

## ⚡ TL;DR - Run This Now

```bash
# Quick test (interactive)
./scripts/quick-test-jwt-auth.sh

# This will:
# 1. Verify Vault is accessible
# 2. Check OIDC auth configuration
# 3. Open browser for authentication
# 4. Obtain JWT token
# 5. Test Vault authentication
# 6. Start MCP server
```

## 📊 How It Works

```
User → Okta → JWT Token → MCP Server → Vault → Secrets
                   ↓
            Impersonates User
            (with their permissions)
```

### Authentication Flow

1. **User authenticates** with Okta/OIDC provider using PKCE flow
2. **Receives JWT/access token** containing user identity claims
3. **MCP Server** receives the JWT token (via env var `VAULT_JWT_TOKEN`)
4. **MCP Server authenticates to Vault** using `auth/oidc/login` with the JWT
5. **Vault validates JWT** and returns a Vault token with user's policies
6. **MCP Server uses Vault token** to access secrets on behalf of the user

## 📁 Key Files

| File | Purpose |
|------|---------|
| [COMPLETE_JWT_AUTH_GUIDE.md](./COMPLETE_JWT_AUTH_GUIDE.md) | Full documentation with all details |
| [scripts/quick-test-jwt-auth.sh](../scripts/quick-test-jwt-auth.sh) | Quick test script (use this first!) |
| [scripts/get-jwt-and-run-mcp.sh](../scripts/get-jwt-and-run-mcp.sh) | Complete PKCE flow + MCP startup |
| [scripts/setup-vault-jwt-auth.sh](../scripts/setup-vault-jwt-auth.sh) | Configure Vault OIDC auth |
| [example.jwt.env.sh](./example.jwt.env.sh) | Example environment configuration |

## 🔧 Implementation Details

### Code Location

The JWT authentication is implemented in:

- **Client Creation**: [pkg/client/client.go](../pkg/client/client.go)
  - `NewVaultClientWithJWT()` - Creates Vault client with JWT auth
  - `CreateVaultClientForSession()` - Checks JWT token first, falls back to direct token

- **Auth Logic**: [pkg/auth/vault_jwt.go](../pkg/auth/vault_jwt.go)
  - `AuthenticateWithJWT()` - Handles JWT → Vault token exchange
  - `LoadVaultJWTConfigFromEnv()` - Loads config from environment

- **Session Management**: [pkg/client/client.go](../pkg/client/client.go)
  - `NewSessionHandler()` - Creates Vault client for each MCP session
  - Automatically uses JWT if `VAULT_JWT_TOKEN` is set

### Environment Variables

```bash
# Required
export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_JWT_TOKEN='eyJraWQiOiJ...'  # From Okta/OIDC

# Optional (with defaults)
export VAULT_JWT_ROLE='mcp-role'         # Default: mcp-role
export VAULT_JWT_AUTH_PATH='oidc'        # Default: oidc
export VAULT_NAMESPACE=''                # Enterprise only
```

## 🎯 Your Current Setup

Based on your vault.log:

```bash
✅ Vault Address: http://127.0.0.1:8200
✅ OIDC auth enabled: auth/oidc/
✅ Policies configured:
   - vault-policy-admin (full access)
   - vault-policy-developer-read (read-only)
```

## 🚦 Quick Start Steps

### Step 1: Verify Vault is Running

```bash
export VAULT_ADDR='http://127.0.0.1:8200'
vault status
```

### Step 2: Run Quick Test Script

```bash
./scripts/quick-test-jwt-auth.sh
```

This script will:
- ✅ Check Vault connectivity
- ✅ Verify OIDC auth is enabled
- ✅ Check JWT role configuration (create if missing)
- ✅ Open browser for authentication
- ✅ Obtain JWT token via PKCE flow
- ✅ Test Vault authentication
- ✅ Save environment configuration
- ✅ Optionally start MCP server

### Step 3: Use the Generated Environment

```bash
# Load environment (path shown by quick-test script)
source /tmp/vault-jwt-test-YYYYMMDD-HHMMSS.sh

# Start MCP Server
./bin/vault-mcp-server streamable-http
```

### Step 4: Test MCP Server

```bash
# List available tools
curl -X POST http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/list"
  }'

# Test list_secrets tool
curl -X POST http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/call",
    "params": {
      "name": "list_secrets",
      "arguments": {
        "path": "secret"
      }
    }
  }'
```

## 🔐 User Impersonation

When you authenticate with JWT, the MCP server impersonates you in Vault:

```bash
# Your JWT contains claims like:
{
  "sub": "00u123abc456",           # Your user ID
  "email": "you@example.com",      # Your email
  "name": "Your Name",             # Your name
  "groups": ["developers", "ops"]  # Your groups
}

# Vault uses these claims to:
# 1. Verify your identity
# 2. Apply policies based on your role
# 3. Issue a Vault token with YOUR permissions
# 4. Log all actions with YOUR user context
```

This means:
- ✅ **Audit trail** shows WHO accessed which secrets
- ✅ **Least privilege** - you only get access to what YOU should have
- ✅ **No shared tokens** - each user has their own session
- ✅ **Automatic expiration** - tokens expire with your JWT

## 🛠️ Configuration Examples

### For Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "vault": {
      "command": "/path/to/vault-mcp-server",
      "args": ["streamable-http"],
      "env": {
        "VAULT_ADDR": "http://127.0.0.1:8200",
        "VAULT_JWT_TOKEN": "your-jwt-token-here",
        "VAULT_JWT_ROLE": "mcp-role",
        "VAULT_JWT_AUTH_PATH": "oidc"
      }
    }
  }
}
```

### For Production

```bash
# Use secure Vault address
export VAULT_ADDR='https://vault.your-company.com'

# Use TLS for MCP server
export MCP_TLS_CERT_FILE='/path/to/cert.pem'
export MCP_TLS_KEY_FILE='/path/to/key.pem'

# Restrict CORS
export MCP_CORS_MODE='strict'
export MCP_ALLOWED_ORIGINS='https://app.your-company.com'

# Enable rate limiting
export MCP_RATE_LIMIT_GLOBAL='10:20'
export MCP_RATE_LIMIT_SESSION='5:10'

# Use JWT authentication
export VAULT_JWT_TOKEN='your-jwt-token'
export VAULT_JWT_ROLE='production-role'
```

## 🐛 Troubleshooting

### "Cannot connect to Vault"

```bash
# Check Vault is running
vault status

# Check address is correct
echo $VAULT_ADDR
```

### "JWT authentication failed"

```bash
# Verify JWT role exists
vault read auth/oidc/role/mcp-role

# Test authentication manually
vault write auth/oidc/login \
  role=mcp-role \
  jwt=$VAULT_JWT_TOKEN

# Check JWT token is valid (decode at jwt.io)
echo $VAULT_JWT_TOKEN | cut -d. -f2 | base64 -d | jq
```

### "OIDC auth method not enabled"

```bash
# Enable OIDC auth
vault auth enable oidc

# Configure it
vault write auth/oidc/config \
    oidc_discovery_url="https://your-domain.okta.com/oauth2/default" \
    oidc_client_id="your-client-id" \
    default_role="mcp-role"
```

## 📚 Learn More

- [Complete JWT Auth Guide](./COMPLETE_JWT_AUTH_GUIDE.md) - Full documentation
- [JWT Quick Reference](./JWT_QUICK_REFERENCE.md) - Quick commands
- [Okta Setup](./OKTA_SETUP.md) - Configure Okta OIDC
- [Vault JWT Auth](https://www.vaultproject.io/docs/auth/jwt) - Vault docs

## 💡 Tips

1. **JWT tokens expire** - Typically after 1 hour. Re-run the quick test script to get a new token.

2. **Use refresh tokens** - Save the refresh token to get new access tokens without re-authenticating.

3. **Development mode** - For local development, you can use `VAULT_TOKEN` directly instead of JWT.

4. **Production mode** - Always use JWT authentication in production for proper audit trails.

5. **Multiple users** - Each user gets their own JWT token and Vault session.

## 🎉 You're Ready!

Your Vault MCP Server is configured and ready to use JWT authentication. Run the quick test script to get started:

```bash
./scripts/quick-test-jwt-auth.sh
```

Happy coding! 🚀
