# Vault JWT Authentication for MCP Server

This document explains how to use JWT/OIDC tokens to authenticate the MCP Server with HashiCorp Vault.

## Overview

The MCP Server now supports JWT-based authentication with Vault, allowing you to use OAuth 2.0/OIDC access tokens from providers like Okta or Auth0 to authenticate to Vault instead of managing static Vault tokens.

### Authentication Flow

```
User/MCP Client
    ↓
OAuth Provider (Okta/Auth0)
    ↓ (PKCE flow)
Access Token (JWT)
    ↓
MCP Server
    ↓ (JWT auth)
Vault
    ↓
Vault Token
    ↓
Vault Operations
```

## Prerequisites

1. **Vault** running and accessible (e.g., `http://127.0.0.1:8200`)
2. **OIDC Provider** configured (Okta, Auth0, etc.)
3. **Vault OIDC auth method** enabled and configured
4. **JWT role** created in Vault

## Setup Instructions

### 1. Configure Vault JWT Authentication

Run the setup script to configure Vault:

```bash
chmod +x scripts/setup-vault-jwt-auth.sh
./scripts/setup-vault-jwt-auth.sh
```

Or manually configure Vault:

```bash
# Enable OIDC auth method
vault auth enable oidc

# Configure OIDC
vault write auth/oidc/config \
    oidc_discovery_url="https://your-domain.okta.com/oauth2/default" \
    oidc_client_id="your-client-id" \
    default_role="mcp-role"

# Create JWT role (note: role_type="jwt" is crucial!)
vault write auth/oidc/role/mcp-role \
    role_type="jwt" \
    bound_audiences="api://default" \
    user_claim="sub" \
    policies="vault-policy-admin" \
    token_ttl=1h \
    token_max_ttl=4h \
    oidc_scopes="openid,profile,email"
```

**Important**: The `role_type="jwt"` parameter is required for direct JWT authentication. Without it, Vault expects a browser-based OIDC flow.

### 2. Obtain JWT Token from Your OIDC Provider

#### Option A: Use the Automated Script

```bash
chmod +x scripts/get-jwt-and-run-mcp.sh
./scripts/get-jwt-and-run-mcp.sh
```

This script will:
1. Generate PKCE codes
2. Open your browser for authentication
3. Exchange the authorization code for an access token
4. Test Vault authentication
5. Save environment variables
6. Optionally start the MCP Server

#### Option B: Manual PKCE Flow

See the example in `docs/# Step 1: Generate PKCE codes and save t` for the complete manual flow.

### 3. Configure Environment Variables

Set the following environment variables for the MCP Server:

```bash
# Required: Vault address
export VAULT_ADDR='http://127.0.0.1:8200'

# Required: JWT token from your OIDC provider
export VAULT_JWT_TOKEN='eyJraWQiOiJpa0...'

# Optional: JWT role (default: mcp-role)
export VAULT_JWT_ROLE='mcp-role'

# Optional: Auth path (default: oidc)
export VAULT_JWT_AUTH_PATH='oidc'

# Optional: Vault namespace (for Vault Enterprise)
export VAULT_NAMESPACE='my-namespace'
```

### 4. Run the MCP Server

Start the MCP Server with JWT authentication:

```bash
./bin/vault-mcp-server streamable-http
```

The server will automatically:
1. Detect the `VAULT_JWT_TOKEN` environment variable
2. Authenticate to Vault using the JWT
3. Obtain a Vault token
4. Use that token for all Vault operations

## Environment Variables

### JWT Authentication (Priority Order)

The MCP Server checks for authentication credentials in this order:

1. **JWT Authentication** (if `VAULT_JWT_TOKEN` is set)
   - `VAULT_JWT_TOKEN` - JWT/access token from OIDC provider
   - `VAULT_JWT_ROLE` - Vault JWT role (default: `mcp-role`)
   - `VAULT_JWT_AUTH_PATH` - Vault auth path (default: `oidc`)

2. **Token Authentication** (if `VAULT_TOKEN` is set)
   - `VAULT_TOKEN` - Direct Vault token

### Common Variables

- `VAULT_ADDR` - Vault server address (default: `http://127.0.0.1:8200`)
- `VAULT_NAMESPACE` - Vault namespace (Enterprise only)
- `VAULT_SKIP_VERIFY` - Skip TLS verification (default: `false`)

## Testing JWT Authentication

### Test Direct Vault Authentication

```bash
vault write auth/oidc/login \
    role=mcp-role \
    jwt=$VAULT_JWT_TOKEN
```

Expected output:
```
Key                  Value
---                  -----
token                hvs.CAESI...
token_accessor       zIVamnEF...
token_duration       1h
token_renewable      true
token_policies       ["default" "vault-policy-admin"]
```

### Test MCP Server Authentication

1. Start the server:
```bash
export VAULT_JWT_TOKEN="your-jwt-token"
./bin/vault-mcp-server streamable-http
```

2. Check the logs for:
```
INFO Using JWT authentication for Vault
INFO Successfully authenticated to Vault using JWT
INFO Created Vault client with JWT authentication
```

### Using MCP Tools

Once authenticated, you can use all Vault MCP tools:

```bash
# List secrets
curl -X POST http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
      "name": "list_secrets",
      "arguments": {
        "path": "secret/metadata"
      }
    }
  }'
```

## Token Lifecycle Management

### Token Expiration

JWT tokens typically have a short lifetime (e.g., 1 hour). The Vault token obtained through JWT authentication inherits the TTL configured in the JWT role.

**Note**: Token refresh is not yet automatic. You'll need to:
1. Obtain a new JWT token from your OIDC provider
2. Update the `VAULT_JWT_TOKEN` environment variable
3. Restart the MCP Server

### Monitoring Token Status

The MCP Server logs important authentication events:
- Initial JWT authentication
- Token TTL and renewal status
- Authentication errors

## Troubleshooting

### Error: "role with oidc role_type is not allowed"

**Cause**: The Vault role was created without `role_type="jwt"`

**Solution**: Recreate the role with the correct type:
```bash
vault write auth/oidc/role/mcp-role \
    role_type="jwt" \
    bound_audiences="api://default" \
    user_claim="sub" \
    policies="vault-policy-admin"
```

### Error: "JWT authentication failed: invalid audience"

**Cause**: The JWT token's `aud` claim doesn't match `bound_audiences`

**Solution**: Check your JWT token's audience claim and update the role:
```bash
# Decode JWT to check audience
echo $VAULT_JWT_TOKEN | cut -d'.' -f2 | base64 -d 2>/dev/null | jq .aud

# Update role with correct audience
vault write auth/oidc/role/mcp-role \
    role_type="jwt" \
    bound_audiences="your-audience"
```

### Error: "vault token or JWT token not provided for session"

**Cause**: Neither `VAULT_JWT_TOKEN` nor `VAULT_TOKEN` is set

**Solution**: Set one of the authentication methods:
```bash
export VAULT_JWT_TOKEN="your-jwt-token"
# OR
export VAULT_TOKEN="your-vault-token"
```

### Error: "failed to fetch JWKS"

**Cause**: Vault cannot reach the OIDC discovery endpoint

**Solution**: 
1. Check network connectivity
2. Verify the `oidc_discovery_url` is correct
3. Ensure Vault can reach external networks

### JWT Token Expired

**Cause**: The JWT token has expired (check `exp` claim)

**Solution**: Obtain a new JWT token from your OIDC provider

## Security Considerations

1. **Token Storage**: Never commit JWT tokens or Vault tokens to version control
2. **Token Transmission**: Use HTTPS in production environments
3. **Token Rotation**: Implement regular token rotation
4. **Least Privilege**: Assign minimal necessary policies to JWT roles
5. **Audit Logging**: Enable Vault audit logging for JWT authentication events

## Example: Complete Integration

```bash
#!/bin/bash

# 1. Configure Vault
./scripts/setup-vault-jwt-auth.sh

# 2. Get JWT token (automated)
./scripts/get-jwt-and-run-mcp.sh

# 3. Or manually set environment
export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_JWT_TOKEN='your-jwt-token'
export VAULT_JWT_ROLE='mcp-role'

# 4. Start MCP Server
./bin/vault-mcp-server streamable-http

# 5. Use MCP tools
# The server automatically handles JWT -> Vault token conversion
```

## API Reference

### JWT Authentication Functions

#### `NewVaultClientWithJWT`

Creates a Vault client using JWT authentication.

```go
client, err := client.NewVaultClientWithJWT(
    sessionID,
    "http://127.0.0.1:8200",  // vaultAddress
    false,                      // vaultSkipTLSVerify
    jwtToken,                   // JWT token
    "mcp-role",                 // JWT role
    "oidc",                     // auth path
    "",                         // namespace (optional)
    logger,
)
```

### Environment-based Authentication

The `CreateVaultClientForSession` function automatically detects and uses JWT authentication when `VAULT_JWT_TOKEN` is set:

```go
// Automatically uses JWT if VAULT_JWT_TOKEN is set
client, err := client.CreateVaultClientForSession(ctx, session, logger)
```

## Additional Resources

- [Vault JWT/OIDC Auth Method](https://developer.hashicorp.com/vault/docs/auth/jwt)
- [OAuth 2.0 PKCE Flow](https://oauth.net/2/pkce/)
- [Okta OIDC Setup](docs/OKTA_SETUP.md)
- [Auth0 OIDC Setup](docs/AUTH0_SETUP.md)

## Support

For issues or questions:
1. Check the troubleshooting section above
2. Review Vault audit logs
3. Enable debug logging: `export LOG_LEVEL=debug`
4. Open an issue with relevant logs (redact sensitive information)
