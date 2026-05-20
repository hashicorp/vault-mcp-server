# Vault MCP Server - MCP Client Quick Setup

**For Claude Desktop, VS Code, and other MCP clients**

This guide helps you quickly configure JWT authentication with your MCP client.

## Prerequisites

- ✅ Vault running at `http://127.0.0.1:8200`
- ✅ Okta or Auth0 account configured
- ✅ Vault MCP Server installed

## 3-Step Setup

### Step 1: Configure Vault

Run the setup script (only needed once):

```bash
./scripts/setup-vault-jwt-auth.sh
```

Or if you have custom settings in your MCP client config, pass them:

```bash
export OIDC_DISCOVERY_URL="https://your-domain.okta.com/oauth2/default"
export OIDC_CLIENT_ID="your-client-id"
./scripts/setup-vault-jwt-auth.sh
```

### Step 2: Get Your JWT Token

Run the automation script:

```bash
./scripts/get-jwt-and-run-mcp.sh
```

This will:
1. Open your browser for authentication
2. Exchange the code for a JWT token
3. Save environment variables to `/tmp/vault-jwt-env.sh`
4. Display your JWT token

Copy the JWT token shown.

### Step 3: Configure Your MCP Client

#### For Claude Desktop

**File**: `~/Library/Application Support/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "vault-mcp-server": {
      "command": "/absolute/path/to/vault-mcp-server/bin/vault-mcp-server",
      "args": ["streamable-http"],
      "env": {
        "VAULT_ADDR": "http://127.0.0.1:8200",
        "VAULT_JWT_TOKEN": "paste-your-jwt-token-here",
        "VAULT_JWT_ROLE": "mcp-role",
        "VAULT_JWT_AUTH_PATH": "oidc"
      }
    }
  }
}
```

**Steps**:
1. Find your actual binary path: `pwd`/bin/vault-mcp-server
2. Paste the JWT token from Step 2
3. Save the file
4. Restart Claude Desktop

#### For VS Code

**File**: `.vscode/settings.json`

```json
{
  "mcp.servers": {
    "vault-mcp-server": {
      "command": "/absolute/path/to/vault-mcp-server/bin/vault-mcp-server",
      "args": ["streamable-http"],
      "env": {
        "VAULT_ADDR": "http://127.0.0.1:8200",
        "VAULT_JWT_TOKEN": "${input:vaultJwtToken}",
        "VAULT_JWT_ROLE": "mcp-role"
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

VS Code will prompt for your token when needed.

## Verify It's Working

1. Restart your MCP client
2. Check for these log messages:
   ```
   ✓ Using JWT authentication for Vault
   ✓ Successfully authenticated to Vault using JWT
   ```
3. Test by asking your MCP client:
   ```
   "List secrets in Vault at path secret/metadata"
   ```

## Customizing for Your Environment

### Using Your Own Okta/Auth0 Settings

Instead of getting a token manually, configure the automation script in your mcp.json:

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

The script will use these settings instead of the defaults.

## Templates and Examples

### Quick Start Templates

1. **Minimal** - Just JWT auth:
   ```bash
   cp docs/mcp.json.minimal ~/Library/Application\ Support/Claude/claude_desktop_config.json
   ```

2. **Full Template** - All options:
   ```bash
   cp docs/mcp.json.template ~/Library/Application\ Support/Claude/claude_desktop_config.json
   ```

### More Examples

See [docs/MCP_CONFIG_EXAMPLES.md](MCP_CONFIG_EXAMPLES.md) for:
- Different MCP clients (Claude Desktop, VS Code, etc.)
- Auth0 configuration
- Production TLS setup
- Docker-based deployment

## Common Issues

| Problem | Solution |
|---------|----------|
| "command not found" | Use absolute path to binary: `pwd`/bin/vault-mcp-server |
| "JWT token not provided" | Check `VAULT_JWT_TOKEN` is in your mcp.json |
| "Invalid JSON" | Validate JSON at jsonlint.com |
| Token expired (after 1 hour) | Get a new token with Step 2 |
| Can't connect to Vault | Ensure Vault is running: `vault status` |

## Configuration Variables

All variables you can set in mcp.json `env` section:

### Required
- `VAULT_ADDR` - Vault server address
- `VAULT_JWT_TOKEN` - Your JWT token

### Optional (with defaults)
- `VAULT_JWT_ROLE` - Vault role name (default: `mcp-role`)
- `VAULT_JWT_AUTH_PATH` - Auth path (default: `oidc`)
- `VAULT_NAMESPACE` - Vault namespace (Enterprise)

### Okta Settings (for automation script)
- `OKTA_DOMAIN` - Your Okta domain
- `OKTA_CLIENT_ID` - OAuth client ID
- `OKTA_REDIRECT_URI` - Redirect URI
- `OKTA_AUTHORIZATION_SERVER` - Auth server ID

### Server Settings
- `TRANSPORT_HOST` - Server host (default: `127.0.0.1`)
- `TRANSPORT_PORT` - Server port (default: `8080`)
- `LOG_LEVEL` - Logging level (default: `info`)

## Token Refresh

JWT tokens expire after ~1 hour. When that happens:

1. Run the automation script again: `./scripts/get-jwt-and-run-mcp.sh`
2. Copy the new token
3. Update your mcp.json
4. Restart your MCP client

Or use the automation script directly in mcp.json (see "Customizing for Your Environment" above).

## Need More Help?

- 📖 [Complete Configuration Guide](MCP_CLIENT_JWT_CONFIG.md)
- 📝 [Configuration Examples](MCP_CONFIG_EXAMPLES.md)
- ⚡ [Quick Reference](JWT_QUICK_REFERENCE.md)
- 🔧 [Troubleshooting](VAULT_JWT_AUTH.md#troubleshooting)

## What's Next?

Once configured, you can:
- 🔐 Read/write secrets
- 📋 List secrets
- 🗂️ Manage mounts
- 🔑 Issue PKI certificates
- 🛠️ And more!

Just ask your MCP client to interact with Vault, and it will use your authenticated session automatically.

---

**Quick Links**:
- [MCP Client Configuration](MCP_CLIENT_JWT_CONFIG.md) - Detailed setup guide
- [Configuration Examples](MCP_CONFIG_EXAMPLES.md) - Copy-paste examples
- [JWT Authentication](VAULT_JWT_AUTH.md) - How JWT auth works
- [Quick Reference](JWT_QUICK_REFERENCE.md) - Commands and troubleshooting
