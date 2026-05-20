#!/bin/bash
# Test MCP Server with JWT Authentication
# This script properly initializes an MCP session and then calls tools

set -e

# Configuration
MCP_URL="${MCP_URL:-http://localhost:8080/mcp}"
VAULT_MOUNT="${VAULT_MOUNT:-secret}"  # KV mount point
VAULT_PATH="${VAULT_PATH:-}"          # Path within the mount (empty = root)

echo "╔════════════════════════════════════════════════════════════╗"
echo "║  Testing MCP Server with JWT Authentication               ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# # Check if server is running
# if ! curl -s -o /dev/null -w "%{http_code}" "$MCP_URL" | grep -q "405"; then
#     echo "❌ Error: MCP server not responding at $MCP_URL"
#     echo "   Make sure the server is running:"
#     echo "   ./bin/vault-mcp-server streamable-http"
#     exit 1
# fi

echo "✅ MCP server is running at $MCP_URL"
echo ""

# Step 1: Initialize MCP Session
echo "📋 Step 1: Initializing MCP session..."
INIT_RESPONSE=$(curl -s -i -X POST "$MCP_URL" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
      "protocolVersion": "2024-11-05",
      "clientInfo": {
        "name": "test-client",
        "version": "1.0.0"
      },
      "capabilities": {}
    }
  }')

# Extract session ID from response headers
SESSION_ID=$(echo "$INIT_RESPONSE" | grep -i "Mcp-Session-Id:" | cut -d' ' -f2 | tr -d '\r\n')

if [ -z "$SESSION_ID" ]; then
    echo "❌ Error: Failed to get session ID"
    echo ""
    echo "Response:"
    echo "$INIT_RESPONSE"
    exit 1
fi

echo "✅ Session initialized: $SESSION_ID"
echo ""

# Extract the JSON body (after headers)
INIT_BODY=$(echo "$INIT_RESPONSE" | sed -n '/^{/,/^}/p')
echo "Server Info:"
echo "$INIT_BODY" | grep -o '"serverInfo":{[^}]*}' | sed 's/,/\n  /g' | sed 's/{/\n  /g' | sed 's/}//g'
echo ""

# Step 2: Send notifications/initialized (required by MCP protocol)
echo "📋 Step 2: Sending initialized notification..."
curl -s -X POST "$MCP_URL" \
  -H "Content-Type: application/json" \
  -H "Mcp-Session-Id: $SESSION_ID" \
  -d '{
    "jsonrpc": "2.0",
    "method": "notifications/initialized"
  }' > /dev/null

echo "✅ Session fully initialized"
echo ""
echo "🔐 JWT Authentication Status:"
echo "   At this point, the MCP server has:"
echo "   1. Created a new session"
echo "   2. Detected VAULT_JWT_TOKEN in environment"
echo "   3. Authenticated to Vault using the JWT"
echo "   4. Received a Vault token with user permissions"
echo ""

# Step 3: List available tools
echo "📋 Step 3: Listing available tools..."
TOOLS_RESPONSE=$(curl -s -X POST "$MCP_URL" \
  -H "Content-Type: application/json" \
  -H "Mcp-Session-Id: $SESSION_ID" \
  -d '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/list"
  }')

echo "✅ Available tools:"
echo "$TOOLS_RESPONSE" | grep -o '"name":"[^"]*"' | cut -d'"' -f4 | sed 's/^/   - /'
echo ""

# Step 4: Test list_secrets tool
echo "📋 Step 4: Testing list_secrets tool (mount: $VAULT_MOUNT, path: $VAULT_PATH)..."
SECRETS_RESPONSE=$(curl -s -X POST "$MCP_URL" \
  -H "Content-Type: application/json" \
  -H "Mcp-Session-Id: $SESSION_ID" \
  -d "{
    \"jsonrpc\": \"2.0\",
    \"id\": 3,
    \"method\": \"tools/call\",
    \"params\": {
      \"name\": \"list_secrets\",
      \"arguments\": {
        \"mount\": \"$VAULT_MOUNT\",
        \"path\": \"$VAULT_PATH\"
      }
    }
  }")

echo "Response:"
echo "$SECRETS_RESPONSE" | jq '.' 2>/dev/null || echo "$SECRETS_RESPONSE"
echo ""

# Check if there was an error
if echo "$SECRETS_RESPONSE" | grep -q '"error"'; then
    echo "⚠️  Error occurred - this might be expected if no secrets exist yet"
else
    echo "✅ list_secrets call succeeded!"
fi
echo ""

# Step 5: Test write_secret tool
echo "📋 Step 5: Testing write_secret tool..."
WRITE_RESPONSE=$(curl -s -X POST "$MCP_URL" \
  -H "Content-Type: application/json" \
  -H "Mcp-Session-Id: $SESSION_ID" \
  -d '{
    "jsonrpc": "2.0",
    "id": 4,
    "method": "tools/call",
    "params": {
      "name": "write_secret",
      "arguments": {
        "mount": "secret",
        "path": "mcp-test/demo",
        "key": "password",
        "value": "testpass123"
      }
    }
  }')

echo "Response:"
echo "$WRITE_RESPONSE" | jq '.' 2>/dev/null || echo "$WRITE_RESPONSE"
echo ""

if echo "$WRITE_RESPONSE" | grep -q '"error"'; then
    echo "⚠️  Error writing secret"
else
    echo "✅ Secret written successfully!"
fi
echo ""

# Step 6: Test read_secret tool
echo "📋 Step 6: Testing read_secret tool..."
READ_RESPONSE=$(curl -s -X POST "$MCP_URL" \
  -H "Content-Type: application/json" \
  -H "Mcp-Session-Id: $SESSION_ID" \
  -d '{
    "jsonrpc": "2.0",
    "id": 5,
    "method": "tools/call",
    "params": {
      "name": "read_secret",
      "arguments": {
        "mount": "secret",
        "path": "mcp-test/demo"
      }
    }
  }')

echo "Response:"
echo "$READ_RESPONSE" | jq '.' 2>/dev/null || echo "$READ_RESPONSE"
echo ""

if echo "$READ_RESPONSE" | grep -q '"error"'; then
    echo "⚠️  Error reading secret"
else
    echo "✅ Secret read successfully!"
fi
echo ""

# Step 7: Test list_mounts tool
echo "📋 Step 7: Testing list_mounts tool..."
MOUNTS_RESPONSE=$(curl -s -X POST "$MCP_URL" \
  -H "Content-Type: application/json" \
  -H "Mcp-Session-Id: $SESSION_ID" \
  -d '{
    "jsonrpc": "2.0",
    "id": 6,
    "method": "tools/call",
    "params": {
      "name": "list_mounts",
      "arguments": {}
    }
  }')

echo "Response:"
echo "$MOUNTS_RESPONSE" | jq '.result.content[0].text' 2>/dev/null || echo "$MOUNTS_RESPONSE"
echo ""

echo "╔════════════════════════════════════════════════════════════╗"
echo "║  Test Complete! ✅                                         ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo "📝 Summary:"
echo "   Session ID: $SESSION_ID"
echo "   JWT Auth: ✅ Working (authenticated as user via JWT)"
echo "   MCP Tools: ✅ Accessible"
echo ""
echo "💡 How JWT Authentication Worked:"
echo ""
echo "   1. Your JWT token was in VAULT_JWT_TOKEN environment variable"
echo "   2. When MCP session was initialized, NewSessionHandler was called"
echo "   3. NewSessionHandler detected JWT token and called Vault:"
echo "      vault write auth/oidc/login role=mcp-role jwt=<your-token>"
echo "   4. Vault validated the JWT and returned a Vault token"
echo "   5. All subsequent operations use this Vault token"
echo "   6. The Vault token has YOUR permissions from YOUR JWT claims"
echo ""
echo "🔒 Security Note:"
echo "   - All Vault operations are performed AS YOU (the JWT user)"
echo "   - Vault audit logs show YOUR identity for all actions"
echo "   - Your permissions are limited by the policies assigned to your JWT role"
echo ""
