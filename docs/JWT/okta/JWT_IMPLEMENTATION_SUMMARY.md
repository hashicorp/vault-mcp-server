# JWT Authentication Implementation Summary

## Overview

Implemented comprehensive JWT/OIDC authentication support for the Vault MCP Server, allowing programmatic authentication to HashiCorp Vault using OAuth 2.0 access tokens from providers like Okta and Auth0.

## What Was Implemented

### 1. Core Authentication Module (`pkg/auth/vault_jwt.go`)

**New Functions:**
- `AuthenticateWithJWT()` - Authenticates to Vault using a JWT token
- `AuthenticateWithJWTFromEnv()` - Environment-based JWT authentication
- `LoadVaultJWTConfigFromEnv()` - Loads JWT config from environment
- `RefreshVaultToken()` - Refreshes Vault tokens
- `GetJWTTokenInfo()` - Retrieves token information

**Configuration Structure:**
```go
type VaultJWTConfig struct {
    Enabled    bool   // Whether JWT auth is enabled
    Role       string // Vault JWT role name
    AuthPath   string // Vault auth path (default: "oidc")
    JWTToken   string // JWT token for authentication
}
```

### 2. Client Integration (`pkg/client/client.go`)

**Enhanced Functions:**
- `CreateVaultClientForSession()` - Now supports JWT authentication with automatic fallback to token auth
- `NewVaultClientWithJWT()` - New function to create Vault clients using JWT

**Environment Variables Added:**
```go
VaultJWTToken    = "VAULT_JWT_TOKEN"
VaultJWTRole     = "VAULT_JWT_ROLE"
VaultJWTAuthPath = "VAULT_JWT_AUTH_PATH"
```

**Authentication Flow:**
1. Check for `VAULT_JWT_TOKEN` environment variable
2. If present, authenticate using JWT → obtain Vault token
3. If not present, fall back to `VAULT_TOKEN`
4. Store authenticated client in session

### 3. Automation Scripts

**`scripts/setup-vault-jwt-auth.sh`**
- Enables OIDC auth method in Vault
- Configures OIDC discovery URL
- Creates JWT role with proper settings
- Verifies configuration

**`scripts/get-jwt-and-run-mcp.sh`**
- Generates PKCE codes
- Opens browser for OIDC authentication
- Exchanges authorization code for JWT token
- Tests Vault authentication
- Saves environment variables
- Optionally starts MCP Server

### 4. Documentation

**Comprehensive Guides:**
- `docs/VAULT_JWT_AUTH.md` - Complete JWT authentication guide
- `docs/JWT_QUICKSTART.md` - Quick start guide
- `docs/example.jwt.env.sh` - Example environment configuration
- Updated `README.md` with JWT authentication information

**Example Code:**
- `examples/jwt_auth_example.go` - Programmatic usage examples

### 5. Testing

**Test Suite (`pkg/auth/vault_jwt_test.go`):**
- Configuration loading tests
- Error handling tests
- Environment variable tests
- Validation tests

## How to Use

### Quick Start (3 Steps)

1. **Configure Vault:**
```bash
./scripts/setup-vault-jwt-auth.sh
```

2. **Get JWT Token:**
```bash
./scripts/get-jwt-and-run-mcp.sh
```

3. **Use MCP Server:**
```bash
source /tmp/vault-jwt-env.sh
./bin/vault-mcp-server streamable-http
```

### Manual Configuration

```bash
# Set environment variables
export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_JWT_TOKEN='your-jwt-token'
export VAULT_JWT_ROLE='mcp-role'
export VAULT_JWT_AUTH_PATH='oidc'

# Start server
./bin/vault-mcp-server streamable-http
```

### Programmatic Usage

```go
import "github.com/hashicorp/vault-mcp-server/pkg/auth"

// Option 1: From environment
client, err := auth.AuthenticateWithJWTFromEnv(logger)

// Option 2: Explicit config
config := auth.VaultJWTConfig{
    Enabled:  true,
    Role:     "mcp-role",
    AuthPath: "oidc",
    JWTToken: "your-jwt-token",
}
client, err := auth.AuthenticateWithJWT("http://127.0.0.1:8200", config, logger)
```

## Key Features

### 1. Automatic Detection
- MCP Server automatically detects `VAULT_JWT_TOKEN`
- Seamless fallback to token authentication
- No code changes required to existing deployments

### 2. Session Management
- JWT authentication per session
- Automatic Vault token caching
- Session cleanup on disconnect

### 3. Security
- No static Vault tokens required
- Leverages OIDC provider security
- Token rotation support
- Configurable TTL and policies

### 4. Provider Support
- Okta
- Auth0
- Any OIDC-compliant provider

### 5. Comprehensive Logging
- Debug-level JWT authentication logs
- Token TTL and policy information
- Error details for troubleshooting

## Environment Variables

### JWT Authentication
- `VAULT_JWT_TOKEN` - JWT token (required for JWT auth)
- `VAULT_JWT_ROLE` - Vault JWT role (default: `mcp-role`)
- `VAULT_JWT_AUTH_PATH` - Auth path (default: `oidc`)

### Vault Configuration
- `VAULT_ADDR` - Vault address (default: `http://127.0.0.1:8200`)
- `VAULT_NAMESPACE` - Vault namespace (Enterprise)
- `VAULT_SKIP_VERIFY` - Skip TLS verification (default: `false`)

### Traditional Authentication (fallback)
- `VAULT_TOKEN` - Direct Vault token (used if JWT not configured)

## Vault Configuration Requirements

### 1. Enable OIDC Auth Method
```bash
vault auth enable oidc
```

### 2. Configure OIDC
```bash
vault write auth/oidc/config \
    oidc_discovery_url="https://your-domain.okta.com/oauth2/default" \
    oidc_client_id="your-client-id" \
    default_role="mcp-role"
```

### 3. Create JWT Role
```bash
vault write auth/oidc/role/mcp-role \
    role_type="jwt" \
    bound_audiences="api://default" \
    user_claim="sub" \
    policies="vault-policy-admin" \
    token_ttl=1h
```

**Critical**: `role_type="jwt"` is required for direct JWT authentication.

## Architecture

### Authentication Flow

```
┌─────────────────┐
│   MCP Server    │
└────────┬────────┘
         │
         ├─ Check VAULT_JWT_TOKEN?
         │
         ├─ Yes → JWT Auth Flow
         │    │
         │    ├─ Create Vault client
         │    ├─ Call /auth/oidc/login
         │    ├─ Receive Vault token
         │    └─ Store in session
         │
         └─ No → Token Auth Flow
              │
              ├─ Get VAULT_TOKEN
              └─ Create Vault client
```

### Session Lifecycle

```
1. Session Start
   → CreateVaultClientForSession()
   → Detect JWT or Token auth
   → Authenticate to Vault
   → Store client in activeClients map

2. Session Active
   → Reuse cached Vault client
   → All tools use authenticated client
   → Token refreshed if needed

3. Session End
   → EndSessionHandler()
   → Remove from activeClients
   → Clean up resources
```

## Testing

### Unit Tests
```bash
go test ./pkg/auth/... -v
```

### Integration Test
```bash
# 1. Start Vault
vault server -dev

# 2. Configure JWT auth
./scripts/setup-vault-jwt-auth.sh

# 3. Get JWT token and test
./scripts/get-jwt-and-run-mcp.sh
```

### Manual Verification
```bash
# Test direct Vault authentication
vault write auth/oidc/login \
    role=mcp-role \
    jwt=$VAULT_JWT_TOKEN

# Test MCP Server
export VAULT_JWT_TOKEN="your-token"
./bin/vault-mcp-server streamable-http

# Check logs for:
# "Using JWT authentication for Vault"
# "Successfully authenticated to Vault using JWT"
```

## Troubleshooting

### Common Issues and Solutions

| Error | Cause | Solution |
|-------|-------|----------|
| "role with oidc role_type is not allowed" | Role created without `role_type="jwt"` | Recreate role with `role_type="jwt"` |
| "JWT authentication failed: invalid audience" | Token audience doesn't match `bound_audiences` | Update role with correct audience |
| "vault token or JWT token not provided" | Neither auth method configured | Set `VAULT_JWT_TOKEN` or `VAULT_TOKEN` |
| Token expired | JWT token TTL exceeded | Obtain new JWT token |

### Debug Logging

Enable debug logging for detailed authentication info:
```bash
export LOG_LEVEL=debug
./bin/vault-mcp-server streamable-http
```

## Future Enhancements

Potential improvements for future iterations:
- [ ] Automatic JWT token refresh
- [ ] Token caching and reuse across sessions
- [ ] Support for client credentials flow
- [ ] Vault token renewal automation
- [ ] Metrics for authentication success/failure
- [ ] Support for multiple auth methods per session

## Files Modified/Created

### New Files
- `pkg/auth/vault_jwt.go` - JWT authentication implementation
- `pkg/auth/vault_jwt_test.go` - Test suite
- `scripts/setup-vault-jwt-auth.sh` - Vault configuration script
- `scripts/get-jwt-and-run-mcp.sh` - Complete automation script
- `docs/VAULT_JWT_AUTH.md` - Comprehensive documentation
- `docs/JWT_QUICKSTART.md` - Quick start guide
- `docs/example.jwt.env.sh` - Example environment file
- `examples/jwt_auth_example.go` - Usage examples

### Modified Files
- `pkg/client/client.go` - Added JWT authentication support
- `README.md` - Updated with JWT authentication information

## Backward Compatibility

✅ **Fully backward compatible**
- Existing token-based authentication continues to work
- JWT authentication is opt-in via environment variables
- No breaking changes to existing APIs
- Automatic fallback to token auth if JWT not configured

## Summary

This implementation provides a production-ready JWT authentication system for the Vault MCP Server with:
- ✅ Complete automation scripts
- ✅ Comprehensive documentation
- ✅ Unit tests
- ✅ Example code
- ✅ Backward compatibility
- ✅ Security best practices
- ✅ Error handling and logging
- ✅ Multiple OIDC provider support

The system is ready for immediate use with Okta, Auth0, or any OIDC-compliant provider.
