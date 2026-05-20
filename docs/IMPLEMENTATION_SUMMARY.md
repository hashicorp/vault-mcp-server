# Auth0 Implementation Summary

## Overview
This implementation adds OAuth 2.0 authentication support to the Vault MCP Server using Auth0 as the authorization server. The implementation follows RFC 9728 (OAuth 2.0 Protected Resource Metadata) and the MCP authentication specification.

## What Was Implemented

### 1. Core Authentication Package (`pkg/auth/`)

#### `auth0.go`
- **Auth0Validator**: JWT token validation with JWKS caching
- Token verification: signature, issuer, audience, expiration, and scopes
- Automatic JWKS refresh with 1-hour cache expiry
- RSA public key parsing from JWK format
- Comprehensive error types for different validation failures

#### `metadata.go`
- **ProtectedResourceMetadata**: RFC 9728-compliant metadata structure
- **MetadataHandler**: HTTP handler for `/.well-known/oauth-protected-resource` endpoint
- Protected Resource Metadata document generation
- WWW-Authenticate header construction

#### `middleware.go`
- **AuthMiddleware**: HTTP middleware for token validation
- Bearer token extraction from Authorization header
- Exemption of well-known endpoints and health check from authentication
- Context enrichment with validated token and claims
- Proper 401 responses with WWW-Authenticate header

#### `config.go`
- Configuration loading from environment variables
- Configuration validation
- Server URL construction helpers
- Auth enable/disable checking

### 2. Integration with Main Server

#### Modified Files
- **`cmd/vault-mcp-server/main.go`**: Integrated auth middleware into HTTP server
  - Added auth package import
  - Load and validate Auth0 configuration
  - Create auth middleware
  - Register Protected Resource Metadata endpoint
  - Apply auth middleware to MCP endpoints

### 3. Dependencies

#### Added Go Modules
- `github.com/golang-jwt/jwt/v5` v5.3.1 - JWT parsing and validation

### 4. Documentation

#### `AUTH0_SETUP.md`
Comprehensive documentation covering:
- Authentication flow explanation
- Configuration guide
- Auth0 account and API setup
- Running with authentication enabled
- Testing authentication
- MCP client integration guide
- Security considerations
- Troubleshooting
- Example configurations (Docker, Kubernetes)

#### `example.env.sh`
Example configuration script showing all environment variables including Auth0 settings

#### Updated `README.md`
- Added authentication to features list
- Added Auth0 environment variables section
- Link to detailed auth setup guide

### 5. Tests

#### `pkg/auth/config_test.go`
- Configuration loading tests
- Configuration validation tests
- Helper function tests (URL construction, WWW-Authenticate header)

#### `pkg/auth/middleware_test.go`
- Metadata handler tests
- Middleware tests (disabled, exempt paths, missing token, invalid format)
- Integration tests for authentication flow

## Authentication Flow

1. **Client Request** → MCP server endpoint without token
2. **Server Response** → 401 with `WWW-Authenticate` header pointing to metadata
3. **Metadata Discovery** → Client fetches `/.well-known/oauth-protected-resource`
4. **Authorization Server Discovery** → Client discovers Auth0 endpoints
5. **User Authorization** → OAuth 2.0 authorization code flow with PKCE
6. **Token Exchange** → Client obtains access token
7. **Authenticated Request** → Client includes `Authorization: Bearer {token}`
8. **Token Validation** → Server validates token and processes request

## Environment Variables

### Required (when auth enabled)
- `MCP_AUTH_ENABLED=true` - Enable authentication
- `AUTH0_DOMAIN` - Auth0 tenant domain (e.g., `your-tenant.us.auth0.com`)
- `AUTH0_AUDIENCE` - API identifier (e.g., `https://api.yourapp.com`)

### Optional
- `AUTH0_ISSUER` - Token issuer (defaults to `https://{AUTH0_DOMAIN}/`)
- `AUTH0_REQUIRED_SCOPES` - Comma-separated scopes (defaults to `mcp:tools,mcp:resources`)

## Security Features

✅ **JWT Signature Validation** - Using Auth0's JWKS  
✅ **Issuer Verification** - Ensures token from correct Auth0 tenant  
✅ **Audience Verification** - Validates token for this API  
✅ **Expiration Checking** - Rejects expired tokens  
✅ **Scope-based Authorization** - Fine-grained access control  
✅ **JWKS Caching** - Performance optimization with automatic refresh  
✅ **Exempt Endpoints** - Health checks and metadata accessible without auth  
✅ **TLS Support** - Secure transport for production deployments  

## Testing

All tests pass:
```
✓ pkg/auth/config_test.go - Configuration and helpers
✓ pkg/auth/middleware_test.go - Middleware and metadata handler
✓ Build verification successful
```

## Usage Example

```bash
# Enable Auth0 authentication
export MCP_AUTH_ENABLED=true
export AUTH0_DOMAIN=your-tenant.us.auth0.com
export AUTH0_AUDIENCE=https://api.yourapp.com
export AUTH0_REQUIRED_SCOPES=mcp:tools,mcp:resources

# Start server
./bin/vault-mcp-server streamable-http --transport-host localhost --transport-port 8080
```

## API Endpoints

### Protected Resource Metadata
```
GET /.well-known/oauth-protected-resource
```
Returns RFC 9728-compliant metadata including authorization server URL and supported scopes.

### MCP Endpoint (Protected)
```
GET/POST /mcp
Authorization: Bearer {access_token}
```
Main MCP endpoint, requires valid Auth0 token when authentication is enabled.

### Health Check (Exempt)
```
GET /health
```
Health check endpoint, always accessible without authentication.

## Files Created/Modified

### Created
- `pkg/auth/auth0.go` - Auth0 token validation
- `pkg/auth/metadata.go` - Protected Resource Metadata
- `pkg/auth/middleware.go` - Authentication middleware
- `pkg/auth/config.go` - Configuration helpers
- `pkg/auth/config_test.go` - Configuration tests
- `pkg/auth/middleware_test.go` - Middleware tests
- `AUTH0_SETUP.md` - Comprehensive auth setup guide
- `example.env.sh` - Example configuration script

### Modified
- `cmd/vault-mcp-server/main.go` - Integrated auth middleware
- `go.mod` - Added JWT dependency
- `README.md` - Added auth features and configuration

## Backward Compatibility

✅ **Fully backward compatible** - Authentication is disabled by default  
✅ **Opt-in** - Only enabled when `MCP_AUTH_ENABLED=true`  
✅ **No breaking changes** - Existing deployments continue to work  

## Next Steps / Future Enhancements

- [ ] Support for other OAuth providers (Okta, Azure AD, etc.)
- [ ] Token refresh flow support
- [ ] API key authentication alternative
- [ ] Role-based access control (RBAC)
- [ ] Audit logging for authentication events
- [ ] Prometheus metrics for auth operations

## References

- [MCP Specification](https://spec.modelcontextprotocol.io/)
- [RFC 9728: OAuth 2.0 Protected Resource Metadata](https://www.rfc-editor.org/rfc/rfc9728.html)
- [RFC 6750: Bearer Token Usage](https://www.rfc-editor.org/rfc/rfc6750.html)
- [Auth0 Documentation](https://auth0.com/docs)
