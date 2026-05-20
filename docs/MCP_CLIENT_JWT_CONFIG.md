# MCP Client Configuration for JWT Authentication

This guide shows how to configure the MCP client (e.g., Claude Desktop, VS Code) to use JWT authentication with Vault.

## Overview

The MCP client configuration file (`mcp.json` or similar) allows you to pass environment variables to the Vault MCP Server, including OIDC/Okta credentials and Vault JWT authentication settings.

## Configuration File Locations

### Claude Desktop
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux**: `~/.config/Claude/claude_desktop_config.json`

### VS Code
- `.vscode/settings.json` or user settings

## Complete Configuration Example

### Example 1: Claude Desktop with JWT Authentication

```json
{
  "mcpServers": {
    "vault-mcp-server": {
      "command": "/path/to/vault-mcp-server",
      "args": ["streamable-http"],
      "env": {
        "VAULT_ADDR": "http://127.0.0.1:8200",
        "VAULT_JWT_TOKEN": "your-jwt-token-here",
        "VAULT_JWT_ROLE": "mcp-role",
        "VAULT_JWT_AUTH_PATH": "oidc",
        "VAULT_NAMESPACE": "",
        "VAULT_SKIP_VERIFY": "false",
        "TRANSPORT_HOST": "127.0.0.1",
        "TRANSPORT_PORT": "8080",
        "LOG_LEVEL": "info"
      }
    }
  }
}
```

### Example 2: Claude Desktop with Okta Configuration

If you want to use the automated JWT acquisition script, configure Okta settings:

```json
{
  "mcpServers": {
    "vault-mcp-server": {
      "command": "/path/to/scripts/get-jwt-and-run-mcp.sh",
      "env": {
        "OKTA_DOMAIN": "your-domain.okta.com",
        "OKTA_CLIENT_ID": "your-client-id",
        "OKTA_REDIRECT_URI": "http://localhost:3000/callback",
        "OKTA_AUTHORIZATION_SERVER": "default",
        "VAULT_ADDR": "http://127.0.0.1:8200",
        "VAULT_JWT_ROLE": "mcp-role",
        "VAULT_JWT_AUTH_PATH": "oidc"
      }
    }
  }
}
```

### Example 3: VS Code with Input Variables

For VS Code, you can use input variables to prompt for sensitive information:

```json
{
  "mcp.servers": {
    "vault-mcp-server": {
      "command": "/path/to/vault-mcp-server",
      "args": ["streamable-http"],
      "env": {
        "VAULT_ADDR": "http://127.0.0.1:8200",
        "VAULT_JWT_TOKEN": "${input:vaultJwtToken}",
        "VAULT_JWT_ROLE": "mcp-role",
        "VAULT_JWT_AUTH_PATH": "oidc"
      }
    }
  },
  "mcp.inputs": [
    {
      "id": "vaultJwtToken",
      "type": "promptString",
      "description": "Vault JWT Token",
      "password": true
    }
  ]
}
```

### Example 4: With Auth0 Configuration

```json
{
  "mcpServers": {
    "vault-mcp-server": {
      "command": "/path/to/vault-mcp-server",
      "args": ["streamable-http"],
      "env": {
        "VAULT_ADDR": "http://127.0.0.1:8200",
        "VAULT_JWT_TOKEN": "your-auth0-jwt-token",
        "VAULT_JWT_ROLE": "mcp-role",
        "VAULT_JWT_AUTH_PATH": "oidc",
        "MCP_AUTH_ENABLED": "true",
        "AUTH0_DOMAIN": "your-tenant.us.auth0.com",
        "AUTH0_AUDIENCE": "https://api.yourapp.com",
        "AUTH0_REQUIRED_SCOPES": "mcp:tools,mcp:resources"
      }
    }
  }
}
```

## Environment Variables Reference

### Required Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `VAULT_ADDR` | Vault server address | `http://127.0.0.1:8200` |
| `VAULT_JWT_TOKEN` | JWT token from OIDC provider | `eyJraWQiOiJpa0...` |

### Optional Vault JWT Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `VAULT_JWT_ROLE` | Vault JWT role name | `mcp-role` |
| `VAULT_JWT_AUTH_PATH` | Vault auth path | `oidc` |
| `VAULT_NAMESPACE` | Vault namespace (Enterprise) | `""` |
| `VAULT_SKIP_VERIFY` | Skip TLS verification | `false` |

### Okta Configuration Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `OKTA_DOMAIN` | Okta domain | `your-domain.okta.com` |
| `OKTA_CLIENT_ID` | Okta OAuth client ID | `0oa134sny59dhpzhO698` |
| `OKTA_REDIRECT_URI` | OAuth redirect URI | `http://localhost:3000/callback` |
| `OKTA_AUTHORIZATION_SERVER` | Okta auth server ID | `default` |

### Auth0 Configuration Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `AUTH0_DOMAIN` | Auth0 domain | `your-tenant.us.auth0.com` |
| `AUTH0_AUDIENCE` | API identifier | `https://api.yourapp.com` |
| `AUTH0_REQUIRED_SCOPES` | Required scopes | `mcp:tools,mcp:resources` |

### MCP Server Configuration Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `TRANSPORT_HOST` | HTTP server host | `127.0.0.1` |
| `TRANSPORT_PORT` | HTTP server port | `8080` |
| `MCP_ENDPOINT` | HTTP endpoint path | `/mcp` |
| `LOG_LEVEL` | Logging level | `info` |
| `MCP_AUTH_ENABLED` | Enable MCP OAuth auth | `false` |

## Step-by-Step Configuration

### Step 1: Get Your JWT Token

Choose one of these methods:

**Option A: Automated Script**
```bash
./scripts/get-jwt-and-run-mcp.sh
# This will save the token to /tmp/vault-jwt-env.sh
source /tmp/vault-jwt-env.sh
echo $VAULT_JWT_TOKEN
```

**Option B: Manual PKCE Flow**
Follow the [JWT Quick Start Guide](JWT_QUICKSTART.md)

**Option C: Existing Token**
If you already have a JWT token from your OIDC provider, use it directly.

### Step 2: Update MCP Client Configuration

1. Locate your MCP client configuration file
2. Copy one of the examples above
3. Replace `/path/to/vault-mcp-server` with the actual path
4. Update environment variables with your values
5. Save the file

### Step 3: Restart MCP Client

Restart your MCP client (Claude Desktop, VS Code, etc.) to apply the new configuration.

### Step 4: Verify Configuration

Check the MCP server logs for:
```
INFO Using JWT authentication for Vault
INFO Successfully authenticated to Vault using JWT
INFO Created Vault client with JWT authentication
```

## Token Refresh Strategy

JWT tokens typically expire after 1 hour. Here are strategies to handle token refresh:

### Strategy 1: Script-based Token Acquisition

Use the automated script that re-authenticates when needed:

```json
{
  "command": "/path/to/scripts/get-jwt-and-run-mcp.sh"
}
```

This script will prompt for re-authentication when the token expires.

### Strategy 2: External Token Management

Use an external process to manage token refresh and update the configuration file:

```bash
#!/bin/bash
# token-refresh.sh - Run this in cron or systemd timer
while true; do
    # Get new token
    NEW_TOKEN=$(./scripts/get-jwt-token.sh)
    
    # Update configuration file
    jq ".mcpServers.\"vault-mcp-server\".env.VAULT_JWT_TOKEN = \"$NEW_TOKEN\"" \
        ~/Library/Application\ Support/Claude/claude_desktop_config.json > /tmp/config.json
    mv /tmp/config.json ~/Library/Application\ Support/Claude/claude_desktop_config.json
    
    # Sleep for 50 minutes (token is valid for 1 hour)
    sleep 3000
done
```

### Strategy 3: Long-lived Vault Token

After initial JWT authentication, extract the Vault token and use it directly:

```json
{
  "env": {
    "VAULT_ADDR": "http://127.0.0.1:8200",
    "VAULT_TOKEN": "hvs.CAESI...",
    "VAULT_NAMESPACE": ""
  }
}
```

Note: This bypasses JWT authentication but requires manual token management.

## Security Best Practices

### 1. Token Storage

❌ **Don't**: Store JWT tokens in configuration files committed to version control

✅ **Do**: Use environment variables or secure credential storage

```json
{
  "env": {
    "VAULT_JWT_TOKEN": "${env:VAULT_JWT_TOKEN}"
  }
}
```

### 2. File Permissions

Protect your MCP client configuration file:

```bash
# macOS/Linux
chmod 600 ~/Library/Application\ Support/Claude/claude_desktop_config.json
```

### 3. TLS Configuration

Always use TLS in production:

```json
{
  "env": {
    "VAULT_ADDR": "https://vault.example.com:8200",
    "VAULT_SKIP_VERIFY": "false",
    "MCP_TLS_CERT_FILE": "/path/to/cert.pem",
    "MCP_TLS_KEY_FILE": "/path/to/key.pem"
  }
}
```

### 4. Minimal Permissions

Configure Vault policies with minimal required permissions:

```hcl
# mcp-role-policy.hcl
path "secret/data/myapp/*" {
  capabilities = ["read", "list"]
}
```

## Troubleshooting

### Token Not Found

**Error**: `vault token or JWT token not provided for session`

**Solution**: Verify `VAULT_JWT_TOKEN` is set in your configuration:
```json
{
  "env": {
    "VAULT_JWT_TOKEN": "your-token-here"
  }
}
```

### Invalid Configuration

**Error**: `JWT authentication failed: invalid audience`

**Solution**: Ensure your JWT token's `aud` claim matches Vault's `bound_audiences`:
```bash
# Check token audience
echo $VAULT_JWT_TOKEN | cut -d'.' -f2 | base64 -d | jq .aud

# Update Vault role
vault write auth/oidc/role/mcp-role \
    role_type="jwt" \
    bound_audiences="your-correct-audience"
```

### Path Resolution

**Error**: `command not found: /path/to/vault-mcp-server`

**Solution**: Use absolute paths in configuration:
```bash
# Find absolute path
which vault-mcp-server
# or
realpath bin/vault-mcp-server
```

### Environment Variables Not Applied

**Error**: Using default values instead of configured values

**Solution**: 
1. Restart MCP client completely
2. Check configuration file syntax (valid JSON)
3. Verify environment variable names (case-sensitive)

## Complete Working Example

Here's a complete, tested configuration for Claude Desktop on macOS:

```json
{
  "mcpServers": {
    "vault-mcp-server": {
      "command": "/Users/username/vault-mcp-server/bin/vault-mcp-server",
      "args": ["streamable-http"],
      "env": {
        "VAULT_ADDR": "http://127.0.0.1:8200",
        "VAULT_JWT_TOKEN": "eyJraWQiOiJpa0xMd2pYSGd4b0tzeXRpazE1MjdiTzBtVkJ2T1p3REZLRTJvU1ZKU1FVIiwiYWxnIjoiUlMyNTYifQ...",
        "VAULT_JWT_ROLE": "mcp-role",
        "VAULT_JWT_AUTH_PATH": "oidc",
        "TRANSPORT_HOST": "127.0.0.1",
        "TRANSPORT_PORT": "8080",
        "LOG_LEVEL": "info"
      }
    }
  }
}
```

To use this configuration:

1. Replace `/Users/username/vault-mcp-server/bin/vault-mcp-server` with your actual path
2. Replace the JWT token with your valid token from Okta/Auth0
3. Save to `~/Library/Application Support/Claude/claude_desktop_config.json`
4. Restart Claude Desktop
5. Open a new conversation and try using Vault tools

## Additional Resources

- [JWT Quick Start Guide](JWT_QUICKSTART.md)
- [Complete JWT Authentication Guide](VAULT_JWT_AUTH.md)
- [JWT Quick Reference](JWT_QUICK_REFERENCE.md)
- [Okta Setup Guide](OKTA_SETUP.md)
- [Auth0 Setup Guide](AUTH0_SETUP.md)

## Support

For issues with:
- **Vault authentication**: Check Vault logs and audit logs
- **MCP client**: Check client logs and restart the client
- **JWT tokens**: Verify token validity and expiration
- **Configuration**: Validate JSON syntax and environment variables
