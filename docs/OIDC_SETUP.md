# OIDC Authentication Setup Guide

This guide walks you through setting up OIDC (OpenID Connect) authentication for Vault MCP Server.

## Overview

The Vault MCP Server supports OIDC authentication with:
- Authorization Code flow with PKCE (Proof Key for Code Exchange)
- Support for Auth0, Okta, and generic OIDC providers
- Automatic token refresh using refresh tokens
- Persistent token caching for seamless restarts

## Prerequisites

1. A Vault server with JWT auth method configured
2. An OIDC provider account (Auth0, Okta, Google, etc.)
3. Vault MCP Server installed

## Quick Start

### 1. Configure Your OIDC Provider

#### Auth0

1. Log in to [Auth0 Dashboard](https://manage.auth0.com/)
2. Navigate to Applications → Applications → Create Application
3. Choose "Native" application type
4. Note your Domain and Client ID
5. In Settings → Application URIs:
   - **Allowed Callback URLs**: `http://localhost:8765/callback`
   - **Allowed Web Origins**: `http://localhost:8765`
6. In Advanced Settings → Grant Types, ensure these are enabled:
   - Authorization Code
   - Refresh Token
7. Save changes

#### Okta

1. Log in to [Okta Admin Console](https://login.okta.com/)
2. Navigate to Applications → Applications → Create App Integration
3. Choose "OIDC - OpenID Connect" → "Native Application"
4. Configure Grant Types:
   - Authorization Code
   - Refresh Token
5. Set Sign-in redirect URIs: `http://localhost:8765/callback`
6. Note your Client ID and Okta Domain

### 2. Configure Vault JWT Auth Method

```bash
# Enable JWT auth method
vault auth enable jwt

# Configure JWT auth with your OIDC provider
vault write auth/jwt/config \
    oidc_discovery_url="https://your-tenant.us.auth0.com" \
    oidc_client_id="your_client_id" \
    default_role="mcp-role"

# Create a role for MCP access
vault write auth/jwt/role/mcp-role \
    role_type="jwt" \
    bound_audiences="your_client_id" \
    user_claim="sub" \
    policies="mcp-policy" \
    ttl=1h
```

### 3. Configure Vault MCP Server

Create `~/.vault-mcp/config.yaml`:

```yaml
oidc:
  enabled: true
  issuer: "https://your-tenant.us.auth0.com"  # Your OIDC provider
  client_id: "your_client_id_here"
  redirect_uri: "http://localhost:8765/callback"
  scopes:
    - openid
    - profile
    - email
    - offline_access
  auth_timeout: 120s
  request_refresh_token: true
  refresh_threshold: 5m
  vault_token_source: "auto"
```

Or use environment variables:

```bash
export OIDC_ISSUER="https://your-tenant.us.auth0.com"
export OIDC_CLIENT_ID="your_client_id"
export OIDC_SCOPES="openid,profile,email,offline_access"
export VAULT_ADDR="http://127.0.0.1:8200"
export VAULT_JWT_ROLE="mcp-role"
export VAULT_JWT_AUTH_PATH="jwt"
```

### 4. Start the MCP Server

```bash
vault-mcp-server streamable-http

# Or if using the local binary:
./bin/vault-mcp-server streamable-http
```

On first startup, the server will:
1. Open your default browser to the OIDC provider
2. Prompt you to log in
3. Exchange the authorization code for tokens
4. Authenticate with Vault using the ID token
5. Cache tokens at `~/.vault-mcp/auth-cache.json`

Subsequent starts will reuse cached tokens if still valid.

## Configuration Reference

### OIDC Configuration Options

| Option | Description | Default | Required |
|--------|-------------|---------|----------|
| `issuer` | OIDC provider issuer URL | - | Yes |
| `client_id` | OAuth 2.0 client ID | - | Yes |
| `client_secret` | OAuth 2.0 client secret | - | No |
| `redirect_uri` | OAuth callback URL | `http://localhost:8765/callback` | Yes |
| `scopes` | Requested OAuth scopes | `[openid, profile, email]` | Yes |
| `auth_timeout` | Authentication flow timeout | `120s` | No |
| `request_refresh_token` | Request refresh token | `true` | No |
| `refresh_threshold` | Refresh before expiry | `5m` | No |
| `vault_token_source` | Token source mode | `auto` | No |

### Environment Variables

All configuration options can be set via environment variables:

- `OIDC_ISSUER` - OIDC provider issuer URL
- `OIDC_CLIENT_ID` - Client ID
- `OIDC_CLIENT_SECRET` - Client secret (optional)
- `OIDC_REDIRECT_URI` - Callback URL
- `OIDC_SCOPES` - Comma-separated scopes
- `OIDC_AUTH_TIMEOUT_SECONDS` - Auth timeout in seconds
- `OIDC_REQUEST_REFRESH_TOKEN` - `true` or `false`
- `OIDC_REFRESH_THRESHOLD_SECONDS` - Refresh threshold in seconds
- `VAULT_TOKEN_SOURCE` - `oidc`, `static`, or `auto`
- `VAULT_JWT_ROLE` - Vault JWT role name
- `VAULT_JWT_AUTH_PATH` - Vault JWT auth path (default: `oidc`)

## Token Storage

Tokens are stored at `~/.vault-mcp/auth-cache.json` in plaintext. This file contains:
- OIDC access token
- OIDC refresh token
- OIDC ID token
- Vault token
- Token expiry times

**Security Note**: This file is created with `0600` permissions (owner read/write only), but the tokens are stored in plaintext. On shared systems, consider using OS keychain integration in production.

## Token Refresh

The server automatically refreshes tokens when they approach expiry:
- **Silent refresh**: Uses refresh token to get new access token without user interaction
- **Proactive refresh**: Refreshes `refresh_threshold` before expiry (default: 5 minutes)
- **Automatic fallback**: If refresh fails, triggers full re-authentication

## Troubleshooting

### Browser doesn't open

If the browser doesn't open automatically, the URL will be printed to the console:
```
Please open this URL in your browser:
https://your-tenant.us.auth0.com/authorize?...
```

Copy and paste this URL into your browser.

### Callback server port conflict

If port 8765 is already in use, you can change the callback URL:

```bash
export OIDC_REDIRECT_URI="http://localhost:9999/callback"
```

Don't forget to update this in your OIDC provider settings.

### Authentication timeout

If authentication takes longer than 120 seconds, increase the timeout:

```bash
export OIDC_AUTH_TIMEOUT_SECONDS=300  # 5 minutes
```

### Vault authentication fails

Check that:
1. Vault's JWT auth method is configured with your OIDC provider
2. The `bound_audiences` in the Vault role matches your client ID
3. The `user_claim` is set correctly (typically `sub`)
4. Your Vault role has appropriate policies attached

### Token refresh fails

If token refresh fails repeatedly:
1. Check that `offline_access` scope is included
2. Verify your OIDC provider supports refresh tokens
3. Check that refresh token hasn't expired (some providers have separate refresh token TTLs)

### Clear cached tokens

To force re-authentication, delete the cache file:

```bash
rm ~/.vault-mcp/auth-cache.json
```

## Advanced Topics

### Using with stdio Transport

The OIDC flow works with both HTTP and stdio transports. When using stdio mode (e.g., with Claude Desktop), the callback server runs independently on port 8765 while the MCP server communicates via stdin/stdout.

### Multi-user Support

Currently, one MCP server instance is designed for one authenticated user. Each user should run their own MCP server instance.

### Vault Token Renewal

The server tracks Vault token expiry and can:
1. Re-authenticate with Vault using a cached OIDC token
2. Use Vault's token renewal API for renewable tokens

Configure your Vault role with appropriate TTL settings:

```bash
vault write auth/jwt/role/mcp-role \
    ttl=1h \
    max_ttl=24h
```

## Security Best Practices

1. **Use TLS in production**: Don't send tokens over unencrypted connections
2. **Limit token TTLs**: Use short-lived tokens with refresh capabilities
3. **Restrict Vault policies**: Give MCP server only necessary permissions
4. **Rotate credentials**: Regularly rotate client secrets and update configurations
5. **Monitor auth logs**: Check `~/.vault-mcp/auth.log` for suspicious activity
6. **Secure cache files**: Ensure `~/.vault-mcp/` directory has restricted permissions

## Provider-Specific Notes

### Auth0
- Supports refresh tokens by default
- Use `.well-known/openid-configuration` for auto-discovery
- Test with Auth0's test tenants before production

### Okta
- Requires custom authorization server for refresh tokens
- Default server URL: `https://dev-12345.okta.com/oauth2/default`
- Check authorization server settings for refresh token support

### Google
- Client secret required even for native apps
- Refresh tokens only issued with `access_type=offline` and `prompt=consent`
- Add to scopes: `openid profile email`

## Next Steps

- Read the [complete implementation plan](/memories/session/plan.md)
- Review [token exchange configuration](TOKEN_EXCHANGE_CONFIG.md)
- Check [MCP client configuration](MCP_CLIENT_JWT_CONFIG.md)
