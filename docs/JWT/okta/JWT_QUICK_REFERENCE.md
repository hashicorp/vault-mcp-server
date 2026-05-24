# JWT Authentication Quick Reference

## Setup Commands

```bash
# 1. Configure Vault JWT authentication
./scripts/setup-vault-jwt-auth.sh

# 2. Get JWT token and run MCP Server (automated)
./scripts/get-jwt-and-run-mcp.sh

# 3. Load saved environment and run
source /tmp/vault-jwt-env.sh
./bin/vault-mcp-server streamable-http
```

## Environment Variables

```bash
# Required
export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_JWT_TOKEN='your-jwt-token'

# Optional (with defaults)
export VAULT_JWT_ROLE='mcp-role'        # default: mcp-role
export VAULT_JWT_AUTH_PATH='oidc'       # default: oidc
export VAULT_NAMESPACE='my-namespace'   # default: none
```

## Vault Configuration

```bash
# Enable OIDC auth
vault auth enable oidc

# Configure OIDC
vault write auth/oidc/config \
    oidc_discovery_url="https://your-domain.okta.com/oauth2/default" \
    oidc_client_id="your-client-id" \
    default_role="mcp-role"

# Create JWT role (role_type="jwt" is critical!)
vault write auth/oidc/role/mcp-role \
    role_type="jwt" \
    bound_audiences="api://default" \
    user_claim="sub" \
    policies="vault-policy-admin"
```

## Testing

```bash
# Test Vault authentication
vault write auth/oidc/login role=mcp-role jwt=$VAULT_JWT_TOKEN

# Test MCP Server
curl -X POST http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_secrets","arguments":{"path":"secret/metadata"}}}'
```

## Programmatic Usage

```go
// Option 1: Environment-based
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

## Common Issues

| Error | Fix |
|-------|-----|
| "role with oidc role_type is not allowed" | Add `role_type="jwt"` to role |
| "invalid audience" | Match `bound_audiences` in role |
| "vault token or JWT token not provided" | Set `VAULT_JWT_TOKEN` |
| Token expired | Get new JWT token |

## Logs to Check

```
✅ Success indicators:
  "Using JWT authentication for Vault"
  "Successfully authenticated to Vault using JWT"
  "Created Vault client with JWT authentication"

❌ Error indicators:
  "JWT authentication failed"
  "vault token or JWT token not provided"
```

## PKCE Flow (Manual)

```bash
# 1. Generate PKCE codes
CODE_VERIFIER=$(openssl rand -hex 32)
CODE_CHALLENGE=$(echo -n "$CODE_VERIFIER" | openssl dgst -binary -sha256 | openssl base64 -A | tr '+/' '-_' | tr -d '=')

# 2. Open browser with auth URL
open "https://your-domain.okta.com/oauth2/default/v1/authorize?client_id=YOUR_CLIENT_ID&response_type=code&scope=openid%20profile%20email&redirect_uri=http://localhost:3000/callback&code_challenge=$CODE_CHALLENGE&code_challenge_method=S256"

# 3. Exchange code for token
curl -X POST https://your-domain.okta.com/oauth2/default/v1/token \
  -H 'content-type: application/x-www-form-urlencoded' \
  -d "grant_type=authorization_code" \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "redirect_uri=http://localhost:3000/callback" \
  -d "code=AUTH_CODE_FROM_REDIRECT" \
  -d "code_verifier=$CODE_VERIFIER"
```

## Documentation

- Quick Start: [docs/JWT_QUICKSTART.md](JWT_QUICKSTART.md)
- Complete Guide: [docs/VAULT_JWT_AUTH.md](VAULT_JWT_AUTH.md)
- Implementation: [docs/JWT_IMPLEMENTATION_SUMMARY.md](JWT_IMPLEMENTATION_SUMMARY.md)
- Example Config: [docs/example.jwt.env.sh](example.jwt.env.sh)

## Scripts

- `scripts/setup-vault-jwt-auth.sh` - Configure Vault
- `scripts/get-jwt-and-run-mcp.sh` - Complete automation
- `examples/jwt_auth_example.go` - Code examples
