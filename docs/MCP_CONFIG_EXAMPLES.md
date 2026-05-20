# MCP Client Configuration Examples

This file contains ready-to-use configuration examples for different MCP clients.

## Table of Contents

- [Claude Desktop - Basic JWT Auth](#claude-desktop---basic-jwt-auth)
- [Claude Desktop - Full Configuration](#claude-desktop---full-configuration)
- [Claude Desktop - With Okta Variables](#claude-desktop---with-okta-variables)
- [VS Code - With Input Prompts](#vs-code---with-input-prompts)
- [VS Code - From Environment](#vs-code---from-environment)
- [Generic MCP Client](#generic-mcp-client)

---

## Claude Desktop - Basic JWT Auth

**File**: `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS)

```json
{
  "mcpServers": {
    "vault-mcp-server": {
      "command": "/absolute/path/to/vault-mcp-server/bin/vault-mcp-server",
      "args": ["streamable-http"],
      "env": {
        "VAULT_ADDR": "http://127.0.0.1:8200",
        "VAULT_JWT_TOKEN": "eyJraWQiOiJpa0xMd2pYSGd4...",
        "VAULT_JWT_ROLE": "mcp-role",
        "VAULT_JWT_AUTH_PATH": "oidc"
      }
    }
  }
}
```

**Usage**:
1. Replace `/absolute/path/to/vault-mcp-server/bin/vault-mcp-server` with your actual path
2. Get JWT token: `./scripts/get-jwt-and-run-mcp.sh` and copy the token
3. Paste token into `VAULT_JWT_TOKEN`
4. Restart Claude Desktop

---

## Claude Desktop - Full Configuration

**File**: `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS)

```json
{
  "mcpServers": {
    "vault-mcp-server": {
      "command": "/Users/username/vault-mcp-server/bin/vault-mcp-server",
      "args": ["streamable-http"],
      "env": {
        "VAULT_ADDR": "http://127.0.0.1:8200",
        "VAULT_JWT_TOKEN": "eyJraWQiOiJpa0xMd2pYSGd4...",
        "VAULT_JWT_ROLE": "mcp-role",
        "VAULT_JWT_AUTH_PATH": "oidc",
        "VAULT_NAMESPACE": "",
        "VAULT_SKIP_VERIFY": "false",
        "TRANSPORT_HOST": "127.0.0.1",
        "TRANSPORT_PORT": "8080",
        "MCP_ENDPOINT": "/mcp",
        "LOG_LEVEL": "info",
        "MCP_CORS_MODE": "strict",
        "MCP_RATE_LIMIT_GLOBAL": "10:20",
        "MCP_RATE_LIMIT_SESSION": "5:10"
      }
    }
  }
}
```

---

## Claude Desktop - With Okta Variables

Use this configuration with the automated JWT acquisition script.

**File**: `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS)

```json
{
  "mcpServers": {
    "vault-mcp-server": {
      "command": "/Users/username/vault-mcp-server/scripts/get-jwt-and-run-mcp.sh",
      "env": {
        "OKTA_DOMAIN": "your-domain.okta.com",
        "OKTA_CLIENT_ID": "0oa134sny59dhpzhO698",
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

**Note**: This will open a browser for authentication each time Claude Desktop starts.

---

## VS Code - With Input Prompts

**File**: `.vscode/settings.json` or User Settings

```json
{
  "mcp.servers": {
    "vault-mcp-server": {
      "command": "/absolute/path/to/vault-mcp-server/bin/vault-mcp-server",
      "args": ["streamable-http"],
      "env": {
        "VAULT_ADDR": "${input:vaultAddr}",
        "VAULT_JWT_TOKEN": "${input:vaultJwtToken}",
        "VAULT_JWT_ROLE": "${input:vaultJwtRole}",
        "VAULT_JWT_AUTH_PATH": "oidc"
      }
    }
  },
  "mcp.inputs": [
    {
      "id": "vaultAddr",
      "type": "promptString",
      "description": "Vault Address",
      "default": "http://127.0.0.1:8200"
    },
    {
      "id": "vaultJwtToken",
      "type": "promptString",
      "description": "Vault JWT Token",
      "password": true
    },
    {
      "id": "vaultJwtRole",
      "type": "promptString",
      "description": "Vault JWT Role",
      "default": "mcp-role"
    }
  ]
}
```

**Usage**: VS Code will prompt for these values when the MCP server starts.

---

## VS Code - From Environment

**File**: `.vscode/settings.json`

```json
{
  "mcp.servers": {
    "vault-mcp-server": {
      "command": "/absolute/path/to/vault-mcp-server/bin/vault-mcp-server",
      "args": ["streamable-http"],
      "env": {
        "VAULT_ADDR": "${env:VAULT_ADDR}",
        "VAULT_JWT_TOKEN": "${env:VAULT_JWT_TOKEN}",
        "VAULT_JWT_ROLE": "${env:VAULT_JWT_ROLE}",
        "VAULT_JWT_AUTH_PATH": "oidc"
      }
    }
  }
}
```

**Usage**: Set environment variables before launching VS Code:

```bash
export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_JWT_TOKEN='your-token'
export VAULT_JWT_ROLE='mcp-role'
code .
```

---

## Generic MCP Client

For any MCP client that supports JSON configuration:

```json
{
  "servers": {
    "vault-mcp-server": {
      "type": "streamable-http",
      "command": "/path/to/vault-mcp-server",
      "args": ["streamable-http"],
      "environment": {
        "VAULT_ADDR": "http://127.0.0.1:8200",
        "VAULT_JWT_TOKEN": "your-jwt-token",
        "VAULT_JWT_ROLE": "mcp-role",
        "VAULT_JWT_AUTH_PATH": "oidc"
      }
    }
  }
}
```

---

## Configuration with Auth0

Replace Okta configuration with Auth0:

```json
{
  "mcpServers": {
    "vault-mcp-server": {
      "command": "/path/to/vault-mcp-server/bin/vault-mcp-server",
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

---

## Configuration with Traditional Token Auth

If you prefer to use a Vault token instead of JWT:

```json
{
  "mcpServers": {
    "vault-mcp-server": {
      "command": "/path/to/vault-mcp-server/bin/vault-mcp-server",
      "args": ["streamable-http"],
      "env": {
        "VAULT_ADDR": "http://127.0.0.1:8200",
        "VAULT_TOKEN": "hvs.CAESIJ...",
        "VAULT_NAMESPACE": ""
      }
    }
  }
}
```

---

## Production Configuration with TLS

```json
{
  "mcpServers": {
    "vault-mcp-server": {
      "command": "/path/to/vault-mcp-server/bin/vault-mcp-server",
      "args": ["streamable-http"],
      "env": {
        "VAULT_ADDR": "https://vault.example.com:8200",
        "VAULT_JWT_TOKEN": "your-jwt-token",
        "VAULT_JWT_ROLE": "mcp-role",
        "VAULT_JWT_AUTH_PATH": "oidc",
        "VAULT_SKIP_VERIFY": "false",
        "MCP_TLS_CERT_FILE": "/path/to/server-cert.pem",
        "MCP_TLS_KEY_FILE": "/path/to/server-key.pem",
        "TRANSPORT_HOST": "0.0.0.0",
        "TRANSPORT_PORT": "8443",
        "MCP_AUTH_ENABLED": "true",
        "OKTA_DOMAIN": "your-domain.okta.com",
        "OKTA_AUDIENCE": "api://default",
        "LOG_LEVEL": "warn"
      }
    }
  }
}
```

---

## Docker-based Configuration

```json
{
  "mcpServers": {
    "vault-mcp-server": {
      "command": "docker",
      "args": [
        "run",
        "--rm",
        "--network=host",
        "-e", "VAULT_ADDR=http://127.0.0.1:8200",
        "-e", "VAULT_JWT_TOKEN=your-jwt-token",
        "-e", "VAULT_JWT_ROLE=mcp-role",
        "-e", "VAULT_JWT_AUTH_PATH=oidc",
        "vault-mcp-server:latest",
        "streamable-http"
      ]
    }
  }
}
```

---

## Quick Setup Checklist

1. ✅ Copy the appropriate example above
2. ✅ Update the `command` path to your actual binary location
3. ✅ Get a JWT token using `./scripts/get-jwt-and-run-mcp.sh`
4. ✅ Replace `VAULT_JWT_TOKEN` with your actual token
5. ✅ Update `OKTA_DOMAIN`, `OKTA_CLIENT_ID` if using Okta
6. ✅ Verify `VAULT_ADDR` matches your Vault server
7. ✅ Save the configuration file
8. ✅ Restart your MCP client
9. ✅ Test with a Vault operation

---

## Testing Your Configuration

After updating your configuration, test it:

1. **Check MCP Server Logs**:
   Look for these success messages:
   ```
   INFO Using JWT authentication for Vault
   INFO Successfully authenticated to Vault using JWT
   INFO Created Vault client with JWT authentication
   ```

2. **Test a Simple Operation**:
   In your MCP client (Claude Desktop, VS Code), try:
   ```
   "List secrets in Vault at path secret/metadata"
   ```

3. **Verify Connection**:
   ```bash
   curl http://localhost:8080/health
   ```

   Should return:
   ```json
   {
     "status": "ok",
     "service": "vault-mcp-server",
     "transport": "streamable-http",
     "endpoint": "/mcp"
   }
   ```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| "command not found" | Use absolute path to binary |
| "JWT token not provided" | Verify `VAULT_JWT_TOKEN` is set correctly |
| "Invalid JSON" | Validate JSON syntax at jsonlint.com |
| "Connection refused" | Check `VAULT_ADDR` and ensure Vault is running |
| Token expired | Get a new JWT token |

---

## More Information

- [Complete JWT Auth Guide](VAULT_JWT_AUTH.md)
- [MCP Client Configuration Guide](MCP_CLIENT_JWT_CONFIG.md)
- [Quick Start Guide](JWT_QUICKSTART.md)
- [Quick Reference](JWT_QUICK_REFERENCE.md)
