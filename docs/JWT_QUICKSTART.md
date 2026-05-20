# Quick Start: JWT Authentication with Vault MCP Server

This guide shows you how to quickly set up and use JWT authentication with the Vault MCP Server.

## Prerequisites

- Vault running at `http://127.0.0.1:8200`
- Vault root token or admin access
- Okta/Auth0/OIDC provider configured

## 3-Step Setup

### Step 1: Configure Vault

```bash
# Run the automated setup script
./scripts/setup-vault-jwt-auth.sh
```

Or manually:

```bash
vault auth enable oidc

vault write auth/oidc/config \
    oidc_discovery_url="https://your-domain.okta.com/oauth2/default" \
    oidc_client_id="your-client-id" \
    default_role="mcp-role"

vault write auth/oidc/role/mcp-role \
    role_type="jwt" \
    bound_audiences="api://default" \
    user_claim="sub" \
    policies="vault-policy-admin"
```

### Step 2: Get JWT Token

Run the automated script:

```bash
./scripts/get-jwt-and-run-mcp.sh
```

This will open your browser, authenticate, and automatically configure everything.

### Step 3: Use with MCP Server

The script from Step 2 will save environment variables. To use them:

```bash
# Load environment
source /tmp/vault-jwt-env.sh

# Start MCP Server
./bin/vault-mcp-server streamable-http
```

That's it! The MCP Server will automatically use JWT authentication.

## Manual Configuration

If you prefer to configure manually:

```bash
# 1. Set environment variables
export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_JWT_TOKEN='your-jwt-token-from-okta'
export VAULT_JWT_ROLE='mcp-role'
export VAULT_JWT_AUTH_PATH='oidc'

# 2. Test authentication
vault write auth/oidc/login role=$VAULT_JWT_ROLE jwt=$VAULT_JWT_TOKEN

# 3. Start MCP Server
./bin/vault-mcp-server streamable-http
```

## Verify It's Working

Check the server logs for these messages:

```
INFO Using JWT authentication for Vault
INFO Successfully authenticated to Vault using JWT
INFO Created Vault client with JWT authentication
```

## Test MCP Tools

```bash
# Test listing secrets
curl -X POST http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
      "name": "list_secrets",
      "arguments": {"path": "secret/metadata"}
    }
  }'
```

## Common Issues

### "role with oidc role_type is not allowed"

Fix: Add `role_type="jwt"` to your role:

```bash
vault write auth/oidc/role/mcp-role \
    role_type="jwt" \
    bound_audiences="api://default" \
    user_claim="sub" \
    policies="vault-policy-admin"
```

### "vault token or JWT token not provided"

Fix: Make sure `VAULT_JWT_TOKEN` is set:

```bash
export VAULT_JWT_TOKEN='your-token-here'
```

### Token expired

JWT tokens typically expire after 1 hour. Get a new one:

```bash
./scripts/get-jwt-and-run-mcp.sh
```

## Next Steps

- [Complete Documentation](VAULT_JWT_AUTH.md)
- [MCP Client Configuration](MCP_CLIENT_JWT_CONFIG.md) - Configure JWT in mcp.json
- [Configuration Examples](MCP_CONFIG_EXAMPLES.md) - Ready-to-use examples
- [Okta Setup Guide](OKTA_SETUP.md)
- [Security Best Practices](VAULT_JWT_AUTH.md#security-considerations)

## Support

- Enable debug logging: `export LOG_LEVEL=debug`
- Check Vault audit logs
- Review [Troubleshooting Guide](VAULT_JWT_AUTH.md#troubleshooting)
