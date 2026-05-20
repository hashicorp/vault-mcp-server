#!/bin/bash
# Complete end-to-end example: Obtain JWT token from Okta and authenticate to Vault via MCP Server

set -e

# OKTA Configuration (can be overridden via environment variables from mcp.json)
OKTA_DOMAIN="${OKTA_DOMAIN:-integrator-6794552.okta.com}"
OKTA_CLIENT_ID="${OKTA_CLIENT_ID:-0oa134sny59dhpzhO698}"
OKTA_REDIRECT_URI="${OKTA_REDIRECT_URI:-http://localhost:3000/callback}"
OKTA_AUTHORIZATION_SERVER="${OKTA_AUTHORIZATION_SERVER:-default}"

# Vault Configuration (can be overridden via environment variables from mcp.json)
export VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
export VAULT_JWT_ROLE="${VAULT_JWT_ROLE:-mcp-role}"
export VAULT_JWT_AUTH_PATH="${VAULT_JWT_AUTH_PATH:-oidc}"

echo "=== Vault MCP Server - JWT Authentication Flow ==="
echo ""
echo "Configuration:"
echo "  Okta Domain: $OKTA_DOMAIN"
echo "  Okta Client ID: $OKTA_CLIENT_ID"
echo "  Redirect URI: $OKTA_REDIRECT_URI"
echo "  Auth Server: $OKTA_AUTHORIZATION_SERVER"
echo "  Vault Address: $VAULT_ADDR"
echo "  Vault JWT Role: $VAULT_JWT_ROLE"
echo "  Vault Auth Path: $VAULT_JWT_AUTH_PATH"
echo ""

# Step 1: Generate PKCE codes
echo "Step 1: Generating PKCE codes..."
CODE_VERIFIER=$(openssl rand -hex 32)
CODE_CHALLENGE=$(printf '%s' "$CODE_VERIFIER" \
  | openssl dgst -binary -sha256 \
  | openssl base64 -A \
  | tr '+/' '-_' \
  | tr -d '=')

echo "✓ PKCE codes generated"
echo ""

# Step 2: Build authorization URL
AUTH_URL="https://${OKTA_DOMAIN}/oauth2/${OKTA_AUTHORIZATION_SERVER}/v1/authorize"
AUTH_URL="${AUTH_URL}?client_id=${OKTA_CLIENT_ID}"
AUTH_URL="${AUTH_URL}&response_type=code"
AUTH_URL="${AUTH_URL}&scope=openid%20profile%20email%20mcp:tools%20mcp:resources"
AUTH_URL="${AUTH_URL}&redirect_uri=${OKTA_REDIRECT_URI}"
AUTH_URL="${AUTH_URL}&state=random_state_string"
AUTH_URL="${AUTH_URL}&code_challenge=${CODE_CHALLENGE}"
AUTH_URL="${AUTH_URL}&code_challenge_method=S256"

echo "Step 2: Opening browser for authentication..."
echo "URL: ${AUTH_URL}"
echo ""

# Open browser
if command -v open &> /dev/null; then
    open "$AUTH_URL"
elif command -v xdg-open &> /dev/null; then
    xdg-open "$AUTH_URL"
else
    echo "Please open this URL in your browser:"
    echo "$AUTH_URL"
fi

# Step 3: Get authorization code
echo "Step 3: Waiting for authorization code..."
echo "After login, you'll be redirected to: ${OKTA_REDIRECT_URI}?code=..."
echo ""
read -p "Paste the ENTIRE redirect URL here: " REDIRECT_URL

AUTH_CODE=$(echo "$REDIRECT_URL" | sed -n 's/.*code=\([^&]*\).*/\1/p')

if [ -z "$AUTH_CODE" ]; then
    echo "Error: Could not extract authorization code from URL"
    exit 1
fi

echo "✓ Authorization code extracted"
echo ""

# Step 4: Exchange code for access token
echo "Step 4: Exchanging authorization code for access token..."
TOKEN_RESPONSE=$(curl --silent --request POST \
  --url "https://${OKTA_DOMAIN}/oauth2/${OKTA_AUTHORIZATION_SERVER}/v1/token" \
  --header 'content-type: application/x-www-form-urlencoded' \
  --data "grant_type=authorization_code" \
  --data "client_id=${OKTA_CLIENT_ID}" \
  --data "redirect_uri=${OKTA_REDIRECT_URI}" \
  --data "code=${AUTH_CODE}" \
  --data "code_verifier=${CODE_VERIFIER}")

# Extract access token
ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)

if [ -z "$ACCESS_TOKEN" ]; then
    echo "Error: Failed to obtain access token"
    echo "Response: $TOKEN_RESPONSE"
    exit 1
fi

echo "✓ Access token obtained"
echo ""

# Step 5: Set JWT token for MCP Server
export VAULT_JWT_TOKEN="$ACCESS_TOKEN"

echo "Step 5: Testing Vault authentication with JWT..."
echo ""

# Test Vault JWT authentication directly
echo "Testing direct Vault authentication:"
VAULT_AUTH_RESPONSE=$(vault write -format=json auth/oidc/login \
    role="$VAULT_JWT_ROLE" \
    jwt="$ACCESS_TOKEN")

if [ $? -eq 0 ]; then
    echo "✓ Successfully authenticated to Vault with JWT"
    
    # Extract Vault token
    VAULT_TOKEN=$(echo "$VAULT_AUTH_RESPONSE" | grep -o '"client_token":"[^"]*' | cut -d'"' -f4)
    
    echo ""
    echo "Vault Token Information:"
    echo "$VAULT_AUTH_RESPONSE" | grep -E '"policies"|"lease_duration"|"renewable"'
    echo ""
else
    echo "Error: Vault authentication failed"
    exit 1
fi

# Step 6: Set environment variables for MCP Server
echo "=== Environment Variables for MCP Server ==="
echo ""
echo "export VAULT_ADDR='$VAULT_ADDR'"
echo "export VAULT_JWT_TOKEN='$ACCESS_TOKEN'"
echo "export VAULT_JWT_ROLE='$VAULT_JWT_ROLE'"
echo "export VAULT_JWT_AUTH_PATH='$VAULT_JWT_AUTH_PATH'"
echo ""

# Save to file
cat > /tmp/vault-jwt-env.sh <<EOF
# Vault JWT Authentication Environment Variables
# Generated: $(date)

export VAULT_ADDR='$VAULT_ADDR'
export VAULT_JWT_TOKEN='$ACCESS_TOKEN'
export VAULT_JWT_ROLE='$VAULT_JWT_ROLE'
export VAULT_JWT_AUTH_PATH='$VAULT_JWT_AUTH_PATH'

# Optional: Enable MCP authentication
# export MCP_AUTH_ENABLED='true'

echo "Vault JWT environment loaded"
echo "Access Token (first 20 chars): \${VAULT_JWT_TOKEN:0:20}..."
EOF

echo "Environment variables saved to: /tmp/vault-jwt-env.sh"
echo ""
echo "To use with MCP Server, run:"
echo "  source /tmp/vault-jwt-env.sh"
echo "  ./bin/vault-mcp-server streamable-http"
echo ""

# Step 7: Test MCP Server (optional)
read -p "Do you want to start the MCP Server now? (y/N) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Starting MCP Server with JWT authentication..."
    source /tmp/vault-jwt-env.sh
    ./bin/vault-mcp-server streamable-http
fi

echo ""
echo "=== Complete! ==="
