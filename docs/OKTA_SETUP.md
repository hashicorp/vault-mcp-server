# Okta Authentication for Vault MCP Server

This document describes how to enable and configure Okta OAuth 2.0 authentication for the Vault MCP Server.

## Overview

The Vault MCP Server supports OAuth 2.0 authentication using Okta as the authorization server. This implementation follows the MCP authentication specification and RFC 9728 (OAuth 2.0 Protected Resource Metadata).

## Features

- **JWT Token Validation**: Validates Okta JWT tokens using JWKS (JSON Web Key Sets)
- **Protected Resource Metadata**: Exposes RFC 9728-compliant metadata for OAuth discovery
- **Scope-based Authorization**: Supports fine-grained access control using OAuth scopes
- **Token Caching**: Caches JWKS for performance with automatic refresh
- **Flexible Configuration**: Configure via environment variables
- **Multiple Auth Servers**: Support for Okta custom authorization servers

## Authentication Flow

The authentication flow is identical to Auth0:

1. **Initial Request**: Client makes request without authentication
2. **401 Response**: Server responds with `401 Unauthorized` and `WWW-Authenticate` header pointing to Protected Resource Metadata
3. **Metadata Discovery**: Client fetches Protected Resource Metadata from `/.well-known/oauth-protected-resource`
4. **Authorization Server Discovery**: Client discovers Okta's endpoints via OpenID Discovery
5. **User Authorization**: Client initiates OAuth 2.0 authorization code flow with PKCE
6. **Token Exchange**: Client exchanges authorization code for access token
7. **Authenticated Request**: Client includes access token in `Authorization: Bearer` header
8. **Token Validation**: Server validates token signature, issuer, audience, expiration, and scopes

## Configuration

### Environment Variables

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `MCP_AUTH_ENABLED` | Yes | Enable authentication | `true` |
| `MCP_AUTH_PROVIDER` | No | OAuth provider (auto-detected) | `okta` |
| `OKTA_DOMAIN` | Yes* | Okta domain | `dev-12345.okta.com` |
| `OKTA_AUDIENCE` | Yes* | API identifier | `api://default` |
| `OKTA_ISSUER` | No | Token issuer (auto-detected) | `https://dev-12345.okta.com/oauth2/default` |
| `OKTA_AUTH_SERVER_ID` | No | Authorization server ID (default: `default`) | `custom` |
| `OKTA_REQUIRED_SCOPES` | No | Comma-separated required scopes | `mcp:tools,mcp:resources` |

\* Required when `MCP_AUTH_ENABLED=true` and using Okta

### Default Scopes

If `OKTA_REQUIRED_SCOPES` is not set, the following scopes are required by default:
- `mcp:tools` - Access to MCP tools
- `mcp:resources` - Access to MCP resources

### Provider Auto-Detection

The server automatically detects which OAuth provider to use based on environment variables:
- If `OKTA_DOMAIN` is set → Uses Okta
- If `AUTH0_DOMAIN` is set → Uses Auth0
- You can explicitly set `MCP_AUTH_PROVIDER=okta` to force Okta

## Okta Setup

### 1. Create an Okta Account

If you don't have one already, sign up for a free developer account at [developer.okta.com](https://developer.okta.com)

### 2. Create an Authorization Server

Okta provides a default authorization server, or you can create a custom one:

**Using Default Authorization Server:**
1. Navigate to **Security** → **API** in your Okta admin console
2. You'll see `default` authorization server already available
3. Note the **Issuer URI**: `https://dev-12345.okta.com/oauth2/default`

**Creating Custom Authorization Server:**
1. Go to **Security** → **API** → **Authorization Servers**
2. Click **Add Authorization Server**
3. Set:
   - **Name**: `MCP Server` (or your preferred name)
   - **Audience**: `api://mcp` (use this as `OKTA_AUDIENCE`)
   - **Description**: Your description
4. Click **Save**

### 3. Configure API Scopes

1. In your authorization server settings, go to the **Scopes** tab
2. Add the following scopes:
   - `mcp:tools` - Access MCP tools
   - `mcp:resources` - Access MCP resources
   - `mcp:prompts` - Access MCP prompts (optional)

### 4. Create an Application

The type of application you create depends on your use case:

#### Option A: For Machine-to-Machine (M2M) Authentication (Testing/Scripts)

1. Go to **Applications** → **Applications**
2. Click **Create App Integration**
3. Choose:
   - **Sign-in method**: API Services (OAuth 2.0 Client Credentials)
   - This option is specifically for server-to-server authentication
4. Configure the application:
   - **App integration name**: `MCP Server M2M` (or your preferred name)
5. Click **Save**
6. Note the **Client ID** and **Client Secret**

#### Option B: For User Authentication (Production MCP Clients)

1. Go to **Applications** → **Applications**
2. Click **Create App Integration**
3. Choose:
   - **Sign-in method**: OIDC - OpenID Connect
   - **Application type**: 
     - **Native Application** (for CLI/desktop clients)
     - **Web Application** (for web-based MCP clients)
     - **Single-Page Application** (SPA) (for browser-based clients)
4. Configure the application:
   - **App integration name**: `MCP Client` (or your preferred name)
   - **Grant type**: Check the following based on your needs:
     - ✅ **Authorization Code** (recommended for most clients)
     - ✅ **Refresh Token** (for long-lived sessions)
     - ⚠️ **Client Credentials** (only if you need M2M in addition to user auth)
     - ⚠️ **Implicit** (legacy, not recommended)
   - **Sign-in redirect URIs**: Add your client's redirect URI
     - For testing: `http://localhost:3000/callback`
     - For production: Your actual callback URL (e.g., `https://yourapp.com/callback`)
     - **Important**: You can add multiple URIs for different environments
5. Click **Save**
6. Note the **Client ID** (and **Client Secret** if it's a confidential client)

### 5. Assign the Application

1. Go to the **Assignments** tab of your application
2. Assign users or groups who should have access

### 6. Note Your Configuration

You'll need the following information to configure the MCP server:

- **Domain**: Your Okta domain (e.g., `integrator-6794552.okta.com`)
- **Audience**: The audience/API identifier (e.g., `api://default` or `api://mcp`)
- **Auth Server ID**: The authorization server identifier (e.g., `default` or custom ID)

For testing with client credentials flow:
- **Client ID**: From your API Services application
- **Client Secret**: From your API Services application

For production user authentication:
- **Client ID**: From your OIDC application
- Redirect URIs configured in your application

## Running with Authentication

### Example: Enable Okta Authentication

```bash
export MCP_AUTH_ENABLED=true
export OKTA_DOMAIN=dev-12345.okta.com
export OKTA_AUDIENCE=api://default
export OKTA_AUTH_SERVER_ID=default
export OKTA_REQUIRED_SCOPES=mcp:tools,mcp:resources

./bin/vault-mcp-server streamable-http --transport-host localhost --transport-port 8080
```

### Example: With Custom Authorization Server

```bash
export MCP_AUTH_ENABLED=true
export OKTA_DOMAIN=dev-12345.okta.com
export OKTA_AUDIENCE=api://mcp
export OKTA_AUTH_SERVER_ID=custom
export OKTA_REQUIRED_SCOPES=mcp:tools,mcp:resources

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
  "authorization_servers": ["https://dev-12345.okta.com"],
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

The method to get an access token depends on the type of application you created:

#### Method A: Using Client Credentials Flow (M2M Application)

**Important**: This only works if you created an **API Services** application (Option A above).

```bash
curl --request POST \
  --url https://integrator-6794552.okta.com/oauth2/default/v1/token \
  --header 'content-type: application/x-www-form-urlencoded' \
  --data 'grant_type=client_credentials' \
  --data 'client_id=YOUR_CLIENT_ID' \
  --data 'client_secret=YOUR_CLIENT_SECRET' \
  --data 'scope=mcp:tools mcp:resources'
```

**Troubleshooting**: If you get an "unauthorized_client" error saying the client is not authorized to use client_credentials grant type, your application needs to be configured as **API Services** type, not OIDC.

#### Method B: Using Okta CLI (User Authentication)

```bash
# Install Okta CLI
brew install okta

# Get a token
okta login

# Get access token
okta apps use <app-id>
okta token get --scope mcp:tools,mcp:resources
```

#### Method C: Using Authorization Code Flow (Recommended for user authentication)

This flow requires a web browser and is typically handled by your MCP client automatically. However, you can test it manually:

**Step 1: Generate a Code Verifier and Challenge (for PKCE)**

```bash
# Generate a random code verifier
CODE_VERIFIER=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-43)
echo "Code Verifier: $CODE_VERIFIER"

# Generate code challenge (SHA256 hash of verifier, base64url encoded)
CODE_CHALLENGE=$(echo -n "$CODE_VERIFIER" | openssl dgst -sha256 -binary | base64 | tr -d "=" | tr "/+" "_-")
echo "Code Challenge: $CODE_CHALLENGE"
```

**Step 2: Verify Redirect URI Configuration**

Before opening the authorization URL, ensure your redirect URI is configured in your Okta application:

1. Go to **Applications** → **Applications** → Select your application
2. Click **General** tab
3. Scroll to **LOGIN** section
4. Under **Sign-in redirect URIs**, ensure you have added: `http://localhost:3000/callback`
5. If not present, click **Edit**, add it, and click **Save**

**Step 3: Open the Authorization URL in a Browser**

Replace the placeholders and open this URL in your browser:

```
https://integrator-6794552.okta.com/oauth2/default/v1/authorize?client_id=YOUR_CLIENT_ID&response_type=code&scope=mcp:tools%20mcp:resources&redirect_uri=http://localhost:3000/callback&state=random_state_string&code_challenge=YOUR_CODE_CHALLENGE&code_challenge_method=S256
```

Parameters:
- `client_id`: Your OIDC application client ID
- `response_type`: `code` (for authorization code flow)
- `scope`: `mcp:tools mcp:resources` (URL encoded as `mcp:tools%20mcp:resources`)
- `redirect_uri`: Must match one configured in your Okta application (e.g., `http://localhost:3000/callback`)
- `state`: Random string for CSRF protection
- `code_challenge`: The code challenge you generated above
- `code_challenge_method`: `S256` (SHA256)

**Step 4: User Login and Consent**

1. You'll be redirected to Okta's login page
2. Log in with your Okta credentials
3. Grant consent to the application (if prompted)
4. You'll be redirected back to your `redirect_uri` with a `code` parameter

Example redirect:
```
http://localhost:3000/callback?code=ABC123XYZ&state=random_state_string
```

**Note for Testing**: If you don't have a server running on localhost:3000, you can still complete this flow:
- The browser will attempt to redirect to `http://localhost:3000/callback?code=...`
- Even if it shows an error page, you can copy the full URL from your browser's address bar
- Extract the `code` parameter value from the URL (everything after `code=` and before the next `&`)
- Use this code in Step 5 below

**Step 5: Exchange the Authorization Code for an Access Token**

```bash
curl --request POST \
  --url https://integrator-6794552.okta.com/oauth2/default/v1/token \
  --header 'content-type: application/x-www-form-urlencoded' \
  --data "grant_type=authorization_code" \
  --data "client_id=YOUR_CLIENT_ID" \
  --data "redirect_uri=http://localhost:3000/callback" \
  --data "code=ABC123XYZ" \
  --data "code_verifier=$CODE_VERIFIER"
```

Replace:
- `YOUR_CLIENT_ID`: Your application's client ID
- `ABC123XYZ`: The authorization code from the redirect
- `$CODE_VERIFIER`: The code verifier you generated in Step 1

**Response:**
```json
{
  "token_type": "Bearer",
  "expires_in": 3600,
  "access_token": "eyJraWQiOiJ...",
  "scope": "mcp:tools mcp:resources",
  "refresh_token": "v1.MX..."
}
```

**Note**: For production MCP clients, this entire flow is handled automatically by the client application. The client:
1. Initiates the authorization request
2. Handles the OAuth callback
3. Exchanges the code for tokens
4. Includes the access token in API requests to the MCP server

### 4. Make Authenticated Request

```bash
export ACCESS_TOKEN="your_access_token_here"

curl -H "Authorization: Bearer $ACCESS_TOKEN" \
     http://localhost:8080/mcp
```

## Key Differences from Auth0

| Aspect | Okta | Auth0 |
|--------|------|-------|
| JWKS URL | `https://{domain}/oauth2/{authServerId}/v1/keys` | `https://{domain}/.well-known/jwks.json` |
| Issuer | `https://{domain}/oauth2/{authServerId}` | `https://{domain}/` |
| Auth Server | Supports multiple custom auth servers | Single tenant |
| Default Audience | `api://default` | Custom API identifier |
| Discovery | `/oauth2/{authServerId}/.well-known/openid-configuration` | `/.well-known/openid-configuration` |

## Security Considerations

### Production Deployment

When deploying to production with Okta authentication:

1. **Always use TLS**: Set `MCP_TLS_CERT_FILE` and `MCP_TLS_KEY_FILE`
2. **Use custom authorization server**: Create a dedicated auth server for your MCP API
3. **Define specific scopes**: Create granular scopes for different access levels
4. **Monitor token validation**: Check logs for authentication failures
5. **Rotate secrets**: Regularly rotate client secrets
6. **Configure CORS**: Set appropriate `MCP_ALLOWED_ORIGINS`

### Token Validation

The server validates:
- ✅ Token signature using Okta's JWKS
- ✅ Token issuer matches Okta domain and auth server
- ✅ Token audience matches configured audience
- ✅ Token has not expired
- ✅ Token contains required scopes

## Troubleshooting

### "redirect_uri" parameter error

**Error**: `The 'redirect_uri' parameter must be a Login redirect URI in the client app settings`

**Cause**: The redirect URI you're using in the authorization URL is not configured in your Okta application.

**Solution**:

1. Go to your Okta admin console
2. Navigate to **Applications** → **Applications**
3. Select your application (the one with the Client ID you're using)
4. Click the **General** tab
5. Scroll to the **LOGIN** section
6. Under **Sign-in redirect URIs**, add the exact redirect URI you're using (e.g., `http://localhost:3000/callback`)
7. Click **Save**
8. Try the authorization flow again

**Important Notes**:
- The redirect URI must match exactly (including protocol, host, port, and path)
- `http://localhost:3000/callback` ≠ `http://localhost:3000` ≠ `http://127.0.0.1:3000/callback`
- For testing, you can add multiple redirect URIs (e.g., localhost, 127.0.0.1, production URLs)

### "unauthorized_client" error with client_credentials grant type

**Error**: `The client is not authorized to use the provided grant type. Configured grant types: [authorization_code, implicit].`

**Cause**: Your Okta application is not configured to support the client credentials flow.

**Solution**: You have two options:

1. **Create a new API Services application** (Recommended for M2M):
   - Go to **Applications** → **Applications** → **Create App Integration**
   - Choose **API Services** as the application type
   - This type automatically supports client credentials flow
   
2. **Enable client credentials on existing OIDC application**:
   - Go to your application's **General** tab
   - Scroll to **General Settings** → **Grant type**
   - Click **Edit**
   - Check **Client Credentials**
   - Click **Save**
   - Note: This may not be available for all application types (e.g., SPA)

### Authentication is not working

1. Verify `MCP_AUTH_ENABLED=true`
2. Check Okta configuration variables are set correctly
3. Verify authorization server ID matches your Okta setup
4. Review server logs for authentication errors
5. Verify token is valid using [jwt.io](https://jwt.io)

### Token validation fails

1. Ensure token is not expired
2. Verify audience matches `OKTA_AUDIENCE`
3. Check token has required scopes
4. Confirm Okta domain is correct
5. Verify authorization server ID is correct

### Wrong JWKS URL

If you see JWKS fetch errors, check:
1. Authorization server ID is correct
2. Domain is accessible
3. Network connectivity to Okta

## Example Configuration Files

### Docker Compose

```yaml
version: '3.8'
services:
  vault-mcp-server:
    image: vault-mcp-server
    environment:
      - MCP_AUTH_ENABLED=true
      - OKTA_DOMAIN=dev-12345.okta.com
      - OKTA_AUDIENCE=api://default
      - OKTA_AUTH_SERVER_ID=default
      - OKTA_REQUIRED_SCOPES=mcp:tools,mcp:resources
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
  MCP_AUTH_PROVIDER: "okta"
  OKTA_DOMAIN: "dev-12345.okta.com"
  OKTA_AUDIENCE: "api://default"
  OKTA_AUTH_SERVER_ID: "default"
  OKTA_REQUIRED_SCOPES: "mcp:tools,mcp:resources"
```

## References

- [Okta Developer Documentation](https://developer.okta.com/docs/)
- [Okta OAuth 2.0 API](https://developer.okta.com/docs/reference/api/oidc/)
- [MCP Specification](https://spec.modelcontextprotocol.io/)
- [RFC 9728: OAuth 2.0 Protected Resource Metadata](https://www.rfc-editor.org/rfc/rfc9728.html)
- [RFC 6750: Bearer Token Usage](https://www.rfc-editor.org/rfc/rfc6750.html)
