#!/bin/bash
# Script to configure Vault JWT authentication for MCP Server
# This script sets up Vault to accept JWT tokens from Okta (or other OIDC providers)

set -e

# Configuration (can be overridden via environment variables from mcp.json)
VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
OIDC_DISCOVERY_URL="${OIDC_DISCOVERY_URL:-https://integrator-6794552.okta.com/oauth2/default}"
OIDC_CLIENT_ID="${OIDC_CLIENT_ID:-0oa134sny59dhpzhO698}"
JWT_ROLE="${JWT_ROLE:-mcp-role}"
VAULT_POLICY="${VAULT_POLICY:-vault-policy-admin}"
BOUND_AUDIENCES="${BOUND_AUDIENCES:-api://default}"

echo "=== Configuring Vault JWT Authentication ==="
echo "Vault Address: $VAULT_ADDR"
echo "OIDC Discovery URL: $OIDC_DISCOVERY_URL"
echo "JWT Role: $JWT_ROLE"
echo ""

# Check if Vault is accessible
echo "Checking Vault connectivity..."
if ! vault status > /dev/null 2>&1; then
    echo "Error: Cannot connect to Vault at $VAULT_ADDR"
    echo "Make sure Vault is running and VAULT_ADDR is set correctly"
    exit 1
fi

echo "✓ Vault is accessible"
echo ""

# Enable OIDC auth method if not already enabled
echo "Enabling OIDC auth method..."
if vault auth list | grep -q "oidc/"; then
    echo "✓ OIDC auth method already enabled"
else
    vault auth enable oidc
    echo "✓ OIDC auth method enabled"
fi
echo ""

# Configure OIDC auth method
echo "Configuring OIDC auth method..."
vault write auth/oidc/config \
    oidc_discovery_url="$OIDC_DISCOVERY_URL" \
    oidc_client_id="$OIDC_CLIENT_ID" \
    default_role="$JWT_ROLE"

echo "✓ OIDC auth method configured"
echo ""

# Create JWT role
echo "Creating JWT role: $JWT_ROLE"
vault write auth/oidc/role/$JWT_ROLE \
    role_type="jwt" \
    bound_audiences="$BOUND_AUDIENCES" \
    user_claim="sub" \
    policies="$VAULT_POLICY" \
    token_ttl=1h \
    token_max_ttl=4h \
    oidc_scopes="openid,profile,email"

echo "✓ JWT role created"
echo ""

# Verify configuration
echo "=== Configuration Summary ==="
vault read auth/oidc/config
echo ""
vault read auth/oidc/role/$JWT_ROLE
echo ""

echo "=== Setup Complete ==="
echo ""
echo "Next steps:"
echo "1. Obtain a JWT token from your OIDC provider (Okta)"
echo "2. Set environment variables:"
echo "   export VAULT_ADDR='$VAULT_ADDR'"
echo "   export VAULT_JWT_TOKEN='your-jwt-token'"
echo "   export VAULT_JWT_ROLE='$JWT_ROLE'"
echo "   export VAULT_JWT_AUTH_PATH='oidc'"
echo ""
echo "3. Test authentication:"
echo "   vault write auth/oidc/login role=$JWT_ROLE jwt=\$VAULT_JWT_TOKEN"
echo ""
echo "4. Or use with MCP Server - it will automatically use JWT authentication"
echo "   when VAULT_JWT_TOKEN is set in the environment"
