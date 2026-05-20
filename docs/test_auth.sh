#!/bin/bash
# Test script for Auth0 authentication in Vault MCP Server

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
SERVER_URL="${SERVER_URL:-http://localhost:8080}"
MCP_ENDPOINT="${MCP_ENDPOINT:-/mcp}"

echo "========================================"
echo "Vault MCP Server - Auth0 Test Script"
echo "========================================"
echo ""
echo "Server URL: $SERVER_URL"
echo "MCP Endpoint: $MCP_ENDPOINT"
echo ""

# Test 1: Check if server is running
echo -e "${YELLOW}Test 1: Health Check${NC}"
if curl -s -f "$SERVER_URL/health" > /dev/null; then
    echo -e "${GREEN}✓ Server is running${NC}"
else
    echo -e "${RED}✗ Server is not running${NC}"
    exit 1
fi
echo ""

# Test 2: Check Protected Resource Metadata
echo -e "${YELLOW}Test 2: Protected Resource Metadata${NC}"
METADATA=$(curl -s "$SERVER_URL/.well-known/oauth-protected-resource")
if [ -n "$METADATA" ]; then
    echo -e "${GREEN}✓ Metadata endpoint is accessible${NC}"
    echo "Metadata:"
    echo "$METADATA" | jq '.' 2>/dev/null || echo "$METADATA"
else
    echo -e "${YELLOW}⚠ Metadata endpoint not found (auth might be disabled)${NC}"
fi
echo ""

# Test 3: Attempt unauthenticated request
echo -e "${YELLOW}Test 3: Unauthenticated Request${NC}"
RESPONSE=$(curl -s -i "$SERVER_URL$MCP_ENDPOINT" 2>&1)
STATUS_CODE=$(echo "$RESPONSE" | grep "HTTP/" | head -1 | awk '{print $2}')

if [ "$STATUS_CODE" = "401" ]; then
    echo -e "${GREEN}✓ Server correctly rejects unauthenticated request (401)${NC}"
    WWW_AUTH=$(echo "$RESPONSE" | grep -i "WWW-Authenticate:" | cut -d' ' -f2-)
    if [ -n "$WWW_AUTH" ]; then
        echo "WWW-Authenticate header:"
        echo "  $WWW_AUTH"
    fi
elif [ "$STATUS_CODE" = "200" ]; then
    echo -e "${YELLOW}⚠ Server accepts unauthenticated request (auth is disabled)${NC}"
else
    echo -e "${YELLOW}⚠ Unexpected status code: $STATUS_CODE${NC}"
fi
echo ""

# Test 4: Authenticated request (if token provided)
if [ -n "$AUTH0_TOKEN" ]; then
    echo -e "${YELLOW}Test 4: Authenticated Request${NC}"
    AUTH_RESPONSE=$(curl -s -i -H "Authorization: Bearer $AUTH0_TOKEN" "$SERVER_URL$MCP_ENDPOINT" 2>&1)
    AUTH_STATUS=$(echo "$AUTH_RESPONSE" | grep "HTTP/" | head -1 | awk '{print $2}')
    
    if [ "$AUTH_STATUS" = "200" ]; then
        echo -e "${GREEN}✓ Successfully authenticated request${NC}"
    elif [ "$AUTH_STATUS" = "401" ]; then
        echo -e "${RED}✗ Authentication failed (token might be invalid or expired)${NC}"
    else
        echo -e "${YELLOW}⚠ Unexpected status code: $AUTH_STATUS${NC}"
    fi
else
    echo -e "${YELLOW}Test 4: Skipped (no AUTH0_TOKEN provided)${NC}"
    echo "To test authenticated requests, set AUTH0_TOKEN environment variable:"
    echo "  export AUTH0_TOKEN='your_access_token_here'"
fi
echo ""

# Test 5: Invalid token format
echo -e "${YELLOW}Test 5: Invalid Token Format${NC}"
INVALID_RESPONSE=$(curl -s -i -H "Authorization: Bearer invalid.token.here" "$SERVER_URL$MCP_ENDPOINT" 2>&1)
INVALID_STATUS=$(echo "$INVALID_RESPONSE" | grep "HTTP/" | head -1 | awk '{print $2}')

if [ "$INVALID_STATUS" = "401" ]; then
    echo -e "${GREEN}✓ Server correctly rejects invalid token (401)${NC}"
elif [ "$INVALID_STATUS" = "200" ]; then
    echo -e "${YELLOW}⚠ Server accepts invalid token (auth might be disabled)${NC}"
else
    echo -e "${YELLOW}⚠ Unexpected status code: $INVALID_STATUS${NC}"
fi
echo ""

echo "========================================"
echo "Test Summary"
echo "========================================"
echo ""
echo "All basic tests completed!"
echo ""
echo "To obtain an Auth0 token for testing:"
echo "  1. Using Auth0 CLI:"
echo "     auth0 test token -a YOUR_AUDIENCE"
echo ""
echo "  2. Using Client Credentials:"
echo "     curl --request POST \\"
echo "       --url https://YOUR_DOMAIN/oauth/token \\"
echo "       --header 'content-type: application/json' \\"
echo "       --data '{"
echo "         \"client_id\":\"YOUR_CLIENT_ID\","
echo "         \"client_secret\":\"YOUR_CLIENT_SECRET\","
echo "         \"audience\":\"YOUR_AUDIENCE\","
echo "         \"grant_type\":\"client_credentials\""
echo "       }'"
echo ""
