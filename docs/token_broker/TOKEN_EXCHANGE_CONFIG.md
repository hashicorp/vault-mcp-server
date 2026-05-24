# Token Exchange Configuration Guide

This guide explains how to configure the Vault MCP Server to use RFC 8693 token exchange for Vault authentication.

## Overview

The token exchange flow enables the MCP server to:
1. Authenticate users via OIDC (OpenID Connect)
2. Exchange the OIDC ID token for a scoped JWT token suitable for Vault
3. Use the exchanged token to authenticate with Vault

This follows the authentication flow specified in RFC 8693 (Token Exchange) and RFC 9728 (OAuth 2.0 Protected Resource Metadata).

## Architecture

```
┌─────────────┐       ┌─────────────┐       ┌──────────────┐       ┌───────────┐
│ MCP Client  │──────▶│ MCP Server  │──────▶│Token Broker  │──────▶│   Vault   │
└─────────────┘       └─────────────┘       └──────────────┘       └───────────┘
      │                     │                       │                      │
      │ 1. Login with       │ 2. Validate ID        │ 3. Exchange ID       │
      │    ID Token         │    Token              │    Token for JWT     │
      │                     │                       │                      │
      │                     │ 4. Extract Vault JWT  │ 5. Authenticate      │
      │                     │                       │    with JWT          │
      │                     │                       │                      │
      │ 6. Tool Response    │◀──────────────────────│◀─────────────────────│
```

## Configuration

### Environment Variables

#### Token Exchange Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `TOKEN_EXCHANGE_ENABLED` | No | `false` | Enable token exchange feature |
| `TOKEN_EXCHANGE_BROKER_URL` | Yes* | - | Token broker/exchange endpoint URL |
| `TOKEN_EXCHANGE_CLIENT_ID` | Yes* | - | Client ID for token exchange |
| `TOKEN_EXCHANGE_CLIENT_SECRET` | Yes* | - | Client secret for token exchange |
| `TOKEN_EXCHANGE_AUDIENCE` | No | `vault` | Target audience for exchanged token |
| `TOKEN_EXCHANGE_RESOURCE` | No | - | Target resource URL (e.g., Vault API URL) |
| `TOKEN_EXCHANGE_SCOPES` | No | `vault:read,vault:write` | Comma-separated requested scopes |
| `TOKEN_EXCHANGE_INTROSPECTION_URL` | No | - | Token introspection endpoint (RFC 7662) |

*Required when `TOKEN_EXCHANGE_ENABLED=true`

#### OIDC/OAuth Configuration

Configure one of the following OAuth providers:

**Auth0:**
```bash
export MCP_AUTH_ENABLED=true
export MCP_AUTH_PROVIDER=auth0
export AUTH0_DOMAIN=your-tenant.us.auth0.com
export AUTH0_AUDIENCE=your-api-identifier
export AUTH0_REQUIRED_SCOPES=mcp:tools,mcp:resources
```

**Okta:**
```bash
export MCP_AUTH_ENABLED=true
export MCP_AUTH_PROVIDER=okta
export OKTA_DOMAIN=dev-12345.okta.com
export OKTA_AUDIENCE=api://vault-mcp-server
export OKTA_AUTH_SERVER_ID=default
export OKTA_REQUIRED_SCOPES=mcp:tools,mcp:resources
```

#### Vault Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `VAULT_ADDR` | Yes | `http://127.0.0.1:8200` | Vault server address |
| `VAULT_JWT_ROLE` | No | `mcp-role` | Vault JWT authentication role |
| `VAULT_JWT_AUTH_PATH` | No | `oidc` | Vault JWT auth mount path |
| `VAULT_NAMESPACE` | No | - | Vault namespace (Vault Enterprise) |
| `VAULT_SKIP_VERIFY` | No | `false` | Skip TLS verification (not recommended) |

## Setup Instructions

### 1. Configure OIDC Provider

First, set up authentication with your OIDC provider (Auth0 or Okta). See [AUTH0_SETUP.md](./AUTH0_SETUP.md) or [OKTA_SETUP.md](./OKTA_SETUP.md) for detailed instructions.

### 2. Set Up Token Exchange Broker

If using a token exchange broker service:

```bash
export TOKEN_EXCHANGE_ENABLED=true
export TOKEN_EXCHANGE_BROKER_URL=https://token-broker.example.com/oauth/token
export TOKEN_EXCHANGE_CLIENT_ID=mcp-server-client
export TOKEN_EXCHANGE_CLIENT_SECRET=your-secret-here
export TOKEN_EXCHANGE_AUDIENCE=vault
export TOKEN_EXCHANGE_RESOURCE=https://vault.example.com
export TOKEN_EXCHANGE_SCOPES=vault:read,vault:write
export TOKEN_EXCHANGE_INTROSPECTION_URL=https://idp.example.com/oauth/introspect
```

### 3. Configure Vault JWT Authentication

Set up Vault to accept JWT tokens:

```bash
# Enable JWT auth method
vault auth enable -path=oidc jwt

# Configure JWT auth method
vault write auth/oidc/config \
    oidc_discovery_url="https://your-idp.com" \
    default_role="mcp-role"

# Create a role
vault write auth/oidc/role/mcp-role \
    bound_audiences="vault" \
    user_claim="sub" \
    role_type="jwt" \
    token_policies="mcp-policy" \
    token_ttl=1h
```

### 4. Start the MCP Server

```bash
# With token exchange enabled
export TOKEN_EXCHANGE_ENABLED=true
./vault-mcp-server streamable-http --transport-port 8080
```

## Token Exchange Flow Details

### Step 1: Client Authentication
The MCP client authenticates with the OIDC provider and obtains an ID token.

### Step 2: Request to MCP Server
The client sends a request to the MCP server with the ID token in the Authorization header:
```
Authorization: Bearer <ID_TOKEN>
```

### Step 3: Token Validation
The MCP server validates the ID token using the OIDC provider's JWKS endpoint.

### Step 4: Token Exchange (RFC 8693)
The MCP server exchanges the ID token for a Vault-suitable JWT:

**Request:**
```http
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=<ID_TOKEN>
&subject_token_type=urn:ietf:params:oauth:token-type:id_token
&audience=vault
&scope=vault:read vault:write
&requested_token_type=urn:ietf:params:oauth:token-type:jwt
```

**Response:**
```json
{
  "access_token": "<VAULT_JWT>",
  "issued_token_type": "urn:ietf:params:oauth:token-type:jwt",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "vault:read vault:write"
}
```

### Step 5: Vault Authentication
The MCP server uses the exchanged JWT to authenticate with Vault:

**Request:**
```http
POST /v1/auth/oidc/login
Content-Type: application/json

{
  "role": "mcp-role",
  "jwt": "<VAULT_JWT>"
}
```

**Response:**
```json
{
  "auth": {
    "client_token": "<VAULT_TOKEN>",
    "policies": ["mcp-policy"],
    "lease_duration": 3600,
    "renewable": true
  }
}
```

### Step 6: Tool Execution
The MCP server uses the Vault token to execute requested operations and returns results to the client.

## Simplified Mode (No Token Broker)

If you don't have a token exchange broker, you can use the ID token directly for Vault authentication:

```bash
# Disable token exchange
export TOKEN_EXCHANGE_ENABLED=false

# Configure Vault to accept your OIDC provider's tokens directly
vault write auth/oidc/config \
    oidc_discovery_url="https://your-auth0-domain.auth0.com/" \
    default_role="mcp-role"

vault write auth/oidc/role/mcp-role \
    bound_audiences="your-api-identifier" \
    user_claim="sub" \
    role_type="jwt" \
    token_policies="mcp-policy"
```

In this mode, the MCP server will use the ID token from the OIDC provider directly to authenticate with Vault.

## Testing

### Test Token Exchange Endpoint

```bash
# Test with curl
curl -X POST https://token-broker.example.com/oauth/token \
  -u "client_id:client_secret" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "subject_token=$ID_TOKEN" \
  -d "subject_token_type=urn:ietf:params:oauth:token-type:id_token" \
  -d "audience=vault" \
  -d "scope=vault:read vault:write"
```

### Test Vault JWT Authentication

```bash
# Get JWT token from token exchange
VAULT_JWT="<exchanged-jwt>"

# Test Vault authentication
curl -X POST http://127.0.0.1:8200/v1/auth/oidc/login \
  -d "{\"role\":\"mcp-role\",\"jwt\":\"$VAULT_JWT\"}"
```

## Troubleshooting

### Token Exchange Fails

**Error:** `token exchange request failed`

**Solutions:**
1. Check that `TOKEN_EXCHANGE_BROKER_URL` is correct
2. Verify client credentials (`TOKEN_EXCHANGE_CLIENT_ID` and `TOKEN_EXCHANGE_CLIENT_SECRET`)
3. Check token broker logs for detailed error messages

### Vault Authentication Fails

**Error:** `JWT authentication failed`

**Solutions:**
1. Verify Vault JWT auth is properly configured:
   ```bash
   vault read auth/oidc/config
   vault read auth/oidc/role/mcp-role
   ```
2. Check that the exchanged JWT has the correct audience claim
3. Verify the role name matches: `VAULT_JWT_ROLE=mcp-role`
4. Check Vault logs: `vault audit list` and examine audit logs

### Token Introspection Fails

**Error:** `token introspection failed`

**Solutions:**
1. If `TOKEN_EXCHANGE_INTROSPECTION_URL` is not set, basic JWT validation is used
2. Verify introspection endpoint URL is correct
3. Check that client has permission to introspect tokens

## Security Considerations

1. **Always use HTTPS** for token exchange endpoints in production
2. **Rotate secrets regularly** - Token exchange client secrets should be rotated
3. **Use short-lived tokens** - Configure appropriate TTLs for exchanged tokens
4. **Scope down permissions** - Request minimal scopes needed for operations
5. **Enable audit logging** - Monitor token exchange and Vault authentication events
6. **Validate audiences** - Ensure tokens are bound to specific audiences

## References

- [RFC 8693: OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693)
- [RFC 7662: OAuth 2.0 Token Introspection](https://datatracker.ietf.org/doc/html/rfc7662)
- [RFC 9728: OAuth 2.0 Protected Resource Metadata](https://datatracker.ietf.org/doc/html/rfc9728)
- [Vault JWT/OIDC Auth Method](https://www.vaultproject.io/docs/auth/jwt)
