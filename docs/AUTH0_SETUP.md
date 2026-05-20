# Auth0 Authentication for Vault MCP Server

This document describes how to enable and configure Auth0 OAuth 2.0 authentication for the Vault MCP Server.

## Overview

The Vault MCP Server now supports OAuth 2.0 authentication using Auth0 as the authorization server. This implementation follows the MCP authentication specification and RFC 9728 (OAuth 2.0 Protected Resource Metadata).

## Features

- **JWT Token Validation**: Validates Auth0 JWT tokens using JWKS (JSON Web Key Sets)
- **Protected Resource Metadata**: Exposes RFC 9728-compliant metadata for OAuth discovery
- **Scope-based Authorization**: Supports fine-grained access control using OAuth scopes
- **Token Caching**: Caches JWKS for performance with automatic refresh
- **Flexible Configuration**: Configure via environment variables

## Authentication Flow

When authentication is enabled, the server follows this flow:

1. **Initial Request**: Client makes request without authentication
2. **401 Response**: Server responds with `401 Unauthorized` and `WWW-Authenticate` header pointing to Protected Resource Metadata
3. **Metadata Discovery**: Client fetches Protected Resource Metadata from `/.well-known/oauth-protected-resource`
4. **Authorization Server Discovery**: Client discovers Auth0's endpoints via OpenID Discovery
5. **User Authorization**: Client initiates OAuth 2.0 authorization code flow with PKCE
6. **Token Exchange**: Client exchanges authorization code for access token
7. **Authenticated Request**: Client includes access token in `Authorization: Bearer` header
8. **Token Validation**: Server validates token signature, issuer, audience, expiration, and scopes

## Configuration

### Environment Variables

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `MCP_AUTH_ENABLED` | Yes | Enable authentication | `true` |
| `AUTH0_DOMAIN` | Yes* | Auth0 domain | `your-tenant.us.auth0.com` |
| `AUTH0_AUDIENCE` | Yes* | API identifier | `https://api.yourapp.com` |
| `AUTH0_ISSUER` | No | Token issuer (defaults to `https://{domain}/`) | `https://your-tenant.us.auth0.com/` |
| `AUTH0_REQUIRED_SCOPES` | No | Comma-separated required scopes | `mcp:tools,mcp:resources` |

\* Required when `MCP_AUTH_ENABLED=true`

### Default Scopes

If `AUTH0_REQUIRED_SCOPES` is not set, the following scopes are required by default:
- `mcp:tools` - Access to MCP tools
- `mcp:resources` - Access to MCP resources

## Auth0 Setup

### 1. Create an Auth0 Account

If you don't have one already, sign up at [auth0.com](https://auth0.com)

### 2. Create an API

1. Go to **Applications** → **APIs** in your Auth0 dashboard
2. Click **Create API**
3. Set the following:
   - **Name**: `Vault MCP API` (or your preferred name)
   - **Identifier**: `https://api.yourapp.com` (use this as `AUTH0_AUDIENCE`)
   - **Signing Algorithm**: RS256
4. Click **Create**

### 3. Configure API Scopes

1. In your API settings, go to the **Permissions** tab
2. Add the following scopes:
   - `mcp:tools` - Access MCP tools
   - `mcp:resources` - Access MCP resources
   - `mcp:prompts` - Access MCP prompts (optional)

### 4. Create an Application (Optional)

For testing or if you need a specific client:

1. Go to **Applications** → **Applications**
2. Click **Create Application**
3. Choose **Machine to Machine** or **Single Page Application** depending on your client type
4. Authorize the application to access your API
5. Grant the necessary scopes

### 5. Note Your Configuration

You'll need:
- **Domain**: Found in your Auth0 dashboard (e.g., `your-tenant.us.auth0.com`)
- **Audience**: The API identifier you set (e.g., `https://api.yourapp.com`)

## Running with Authentication

### Example: Enable Auth0 Authentication

```bash
export MCP_AUTH_ENABLED=true
export AUTH0_DOMAIN=your-tenant.us.auth0.com
export AUTH0_AUDIENCE=https://api.yourapp.com
export AUTH0_REQUIRED_SCOPES=mcp:tools,mcp:resources

./bin/vault-mcp-server streamable-http --transport-host localhost --transport-port 8080
```

### Example: Disable Authentication (Default)

```bash
# Authentication is disabled by default
./bin/vault-mcp-server streamable-http --transport-host localhost --transport-port 8080

# Or explicitly disable it
export MCP_AUTH_ENABLED=false
./bin/vault-mcp-server streamable-http
```

## Testing Authentication

### 1. Check Protected Resource Metadata

```bash
curl http://localhost:8080/.well-known/oauth-protected-resource
```

Expected response:
```json
{
  "resource": "http://localhost:8080/mcp",
  "authorization_servers": ["https://your-tenant.us.auth0.com"],
  "scopes_supported": ["mcp:tools", "mcp:resources"],
  "bearer_methods_supported": ["header"],
  "resource_signing_alg_values_supported": ["RS256"]
}
```

### 2. Test Unauthenticated Request

```bash
curl -i http://localhost:8080/mcp
```

Expected response:
```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer realm="mcp", resource_metadata="http://localhost:8080/.well-known/oauth-protected-resource", scope="mcp:tools mcp:resources"
```

### 3. Get an Access Token

#### Using Auth0 CLI

```bash
# Install Auth0 CLI
brew install auth0/auth0-cli/auth0

# Log in
auth0 login

# Get a token
auth0 test token -a https://api.yourapp.com
```

#### Using cURL (Client Credentials Flow)

```bash
curl --request POST \
  --url https://your-tenant.us.auth0.com/oauth/token \
  --header 'content-type: application/json' \
  --data '{
    "client_id":"YOUR_CLIENT_ID",
    "client_secret":"YOUR_CLIENT_SECRET",
    "audience":"https://api.yourapp.com",
    "grant_type":"client_credentials"
  }'
```

### 4. Make Authenticated Request

```bash
export ACCESS_TOKEN="your_access_token_here"

curl -H "Authorization: Bearer $ACCESS_TOKEN" \
     http://localhost:8080/mcp
```

## MCP Client Integration

MCP clients should implement the OAuth 2.0 authorization flow as described in the MCP specification:

1. Attempt to connect to the MCP server
2. Receive 401 response with `WWW-Authenticate` header
3. Parse the `resource_metadata` URL from the header
4. Fetch Protected Resource Metadata
5. Discover authorization server endpoints
6. Initiate OAuth 2.0 authorization code flow with PKCE
7. Store and use the access token for subsequent requests
8. Refresh token when expired

## Security Considerations

### Production Deployment

When deploying to production with authentication enabled:

1. **Always use TLS**: Set `MCP_TLS_CERT_FILE` and `MCP_TLS_KEY_FILE`
2. **Use strong scopes**: Define specific scopes for different access levels
3. **Monitor token validation**: Check logs for authentication failures
4. **Rotate secrets**: Regularly rotate Auth0 client secrets
5. **Configure CORS**: Set appropriate `MCP_ALLOWED_ORIGINS`

### Token Validation

The server validates:
- ✅ Token signature using Auth0's JWKS
- ✅ Token issuer matches Auth0 domain
- ✅ Token audience matches configured audience
- ✅ Token has not expired
- ✅ Token contains required scopes

### Exempt Endpoints

The following endpoints are exempt from authentication:
- `/.well-known/oauth-protected-resource` - Protected Resource Metadata
- `/.well-known/openid-configuration` - OpenID Discovery (redirects to Auth0)
- `/health` - Health check endpoint

## Troubleshooting

### Authentication is not working

1. Verify `MCP_AUTH_ENABLED=true`
2. Check Auth0 configuration variables are set correctly
3. Review server logs for authentication errors
4. Verify token is valid using [jwt.io](https://jwt.io)

### Token validation fails

1. Ensure token is not expired
2. Verify audience matches `AUTH0_AUDIENCE`
3. Check token has required scopes
4. Confirm Auth0 domain is correct

### JWKS fetch errors

1. Check network connectivity to Auth0
2. Verify Auth0 domain is accessible
3. Review firewall rules

## Example Configuration Files

### Docker Compose

```yaml
version: '3.8'
services:
  vault-mcp-server:
    image: vault-mcp-server
    environment:
      - MCP_AUTH_ENABLED=true
      - AUTH0_DOMAIN=your-tenant.us.auth0.com
      - AUTH0_AUDIENCE=https://api.yourapp.com
      - AUTH0_REQUIRED_SCOPES=mcp:tools,mcp:resources
      - MCP_TLS_CERT_FILE=/certs/server.crt
      - MCP_TLS_KEY_FILE=/certs/server.key
    ports:
      - "8080:8080"
    volumes:
      - ./certs:/certs
```

### Kubernetes ConfigMap

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: vault-mcp-config
data:
  MCP_AUTH_ENABLED: "true"
  AUTH0_DOMAIN: "your-tenant.us.auth0.com"
  AUTH0_AUDIENCE: "https://api.yourapp.com"
  AUTH0_REQUIRED_SCOPES: "mcp:tools,mcp:resources"
```

## References

- [MCP Specification](https://spec.modelcontextprotocol.io/)
- [RFC 9728: OAuth 2.0 Protected Resource Metadata](https://www.rfc-editor.org/rfc/rfc9728.html)
- [RFC 6750: Bearer Token Usage](https://www.rfc-editor.org/rfc/rfc6750.html)
- [Auth0 Documentation](https://auth0.com/docs)
- [OAuth 2.0 Authorization Framework](https://oauth.net/2/)
