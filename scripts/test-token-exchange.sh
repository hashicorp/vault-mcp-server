#!/bin/bash
# Test script for Token Exchange + Vault JWT Authentication
# This script verifies the complete authentication flow

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Helper functions
print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_info() {
    echo -e "${YELLOW}ℹ $1${NC}"
}

print_header() {
    echo ""
    echo "=========================================="
    echo "$1"
    echo "=========================================="
}

# Check if required environment variables are set
check_env_vars() {
    print_header "Checking Environment Variables"
    
    local required_vars=(
        "TOKEN_EXCHANGE_ENABLED"
        "TOKEN_EXCHANGE_BROKER_URL"
        "TOKEN_EXCHANGE_CLIENT_ID"
        "TOKEN_EXCHANGE_CLIENT_SECRET"
        "VAULT_ADDR"
        "VAULT_JWT_ROLE"
        "VAULT_JWT_AUTH_PATH"
    )
    
    local missing=0
    for var in "${required_vars[@]}"; do
        if [ -z "${!var}" ]; then
            print_error "$var is not set"
            missing=1
        else
            print_success "$var is set"
        fi
    done
    
    if [ $missing -eq 1 ]; then
        print_error "Missing required environment variables"
        exit 1
    fi
}

# Test token exchange endpoint connectivity
test_token_exchange_endpoint() {
    print_header "Testing Token Exchange Endpoint"
    
    print_info "Checking connectivity to: $TOKEN_EXCHANGE_BROKER_URL"
    
    if curl -s -f -o /dev/null -w "%{http_code}" "$TOKEN_EXCHANGE_BROKER_URL" > /dev/null 2>&1; then
        print_success "Token exchange endpoint is reachable"
    else
        print_error "Cannot reach token exchange endpoint"
        return 1
    fi
}

# Test Vault connectivity
test_vault_connectivity() {
    print_header "Testing Vault Connectivity"
    
    print_info "Checking connectivity to: $VAULT_ADDR"
    
    local health_url="$VAULT_ADDR/v1/sys/health"
    if curl -s -f "$health_url" > /dev/null 2>&1; then
        print_success "Vault is reachable"
    else
        print_error "Cannot reach Vault"
        return 1
    fi
}

# Check Vault JWT auth configuration
check_vault_jwt_auth() {
    print_header "Checking Vault JWT Auth Configuration"
    
    if [ -z "$VAULT_TOKEN" ]; then
        print_error "VAULT_TOKEN not set - cannot check Vault configuration"
        print_info "Set VAULT_TOKEN to an admin token to verify Vault configuration"
        return 1
    fi
    
    print_info "Checking if JWT auth is enabled at path: $VAULT_JWT_AUTH_PATH"
    
    local auth_url="$VAULT_ADDR/v1/sys/auth/$VAULT_JWT_AUTH_PATH"
    if curl -s -H "X-Vault-Token: $VAULT_TOKEN" "$auth_url" | grep -q "jwt"; then
        print_success "JWT auth is enabled at $VAULT_JWT_AUTH_PATH"
    else
        print_error "JWT auth not enabled or not accessible at $VAULT_JWT_AUTH_PATH"
        print_info "Enable with: vault auth enable -path=$VAULT_JWT_AUTH_PATH jwt"
        return 1
    fi
    
    print_info "Checking if role exists: $VAULT_JWT_ROLE"
    local role_url="$VAULT_ADDR/v1/auth/$VAULT_JWT_AUTH_PATH/role/$VAULT_JWT_ROLE"
    if curl -s -H "X-Vault-Token: $VAULT_TOKEN" "$role_url" | grep -q "bound_audiences"; then
        print_success "Role $VAULT_JWT_ROLE exists"
    else
        print_error "Role $VAULT_JWT_ROLE not found"
        print_info "Create with: vault write auth/$VAULT_JWT_AUTH_PATH/role/$VAULT_JWT_ROLE ..."
        return 1
    fi
}

# Test token exchange with a sample token
test_token_exchange() {
    print_header "Testing Token Exchange"
    
    if [ -z "$ID_TOKEN" ]; then
        print_info "ID_TOKEN not provided - skipping token exchange test"
        print_info "Set ID_TOKEN environment variable to test the exchange"
        return 0
    fi
    
    print_info "Attempting token exchange..."
    
    local response=$(curl -s -X POST "$TOKEN_EXCHANGE_BROKER_URL" \
        -u "$TOKEN_EXCHANGE_CLIENT_ID:$TOKEN_EXCHANGE_CLIENT_SECRET" \
        -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
        -d "subject_token=$ID_TOKEN" \
        -d "subject_token_type=urn:ietf:params:oauth:token-type:id_token" \
        -d "audience=${TOKEN_EXCHANGE_AUDIENCE:-vault}" \
        -d "scope=${TOKEN_EXCHANGE_SCOPES:-vault:read,vault:write}" \
        -d "requested_token_type=urn:ietf:params:oauth:token-type:jwt")
    
    if echo "$response" | grep -q "access_token"; then
        print_success "Token exchange successful"
        
        # Extract and display token info
        local access_token=$(echo "$response" | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)
        local expires_in=$(echo "$response" | grep -o '"expires_in":[0-9]*' | cut -d':' -f2)
        
        print_info "Exchanged token expires in: ${expires_in}s"
        
        # Try to use the token with Vault
        test_vault_jwt_auth "$access_token"
    else
        print_error "Token exchange failed"
        print_info "Response: $response"
        return 1
    fi
}

# Test Vault JWT authentication with exchanged token
test_vault_jwt_auth() {
    local jwt_token=$1
    
    print_header "Testing Vault JWT Authentication"
    
    if [ -z "$jwt_token" ]; then
        print_info "No JWT token provided - skipping Vault JWT auth test"
        return 0
    fi
    
    print_info "Attempting Vault authentication with exchanged token..."
    
    local auth_url="$VAULT_ADDR/v1/auth/$VAULT_JWT_AUTH_PATH/login"
    local response=$(curl -s -X POST "$auth_url" \
        -d "{\"role\":\"$VAULT_JWT_ROLE\",\"jwt\":\"$jwt_token\"}")
    
    if echo "$response" | grep -q "client_token"; then
        print_success "Vault JWT authentication successful"
        
        # Extract and display token info
        local policies=$(echo "$response" | grep -o '"policies":\[[^]]*\]' | head -1)
        print_info "Token policies: $policies"
    else
        print_error "Vault JWT authentication failed"
        print_info "Response: $response"
        return 1
    fi
}

# Test MCP server
test_mcp_server() {
    print_header "Testing MCP Server"
    
    local mcp_host="${TRANSPORT_HOST:-127.0.0.1}"
    local mcp_port="${TRANSPORT_PORT:-8080}"
    local mcp_endpoint="${MCP_ENDPOINT:-/mcp}"
    local mcp_url="http://$mcp_host:$mcp_port"
    
    print_info "Checking MCP server health at: $mcp_url/health"
    
    if curl -s -f "$mcp_url/health" | grep -q "ok"; then
        print_success "MCP server is running"
    else
        print_error "MCP server is not responding"
        print_info "Start with: ./vault-mcp-server streamable-http"
        return 1
    fi
    
    # Check protected resource metadata
    print_info "Checking OAuth Protected Resource Metadata"
    local metadata_url="$mcp_url/.well-known/oauth-protected-resource"
    if curl -s -f "$metadata_url" | grep -q "resource"; then
        print_success "Protected Resource Metadata is available"
    else
        print_error "Protected Resource Metadata not found"
        return 1
    fi
}

# Main test flow
main() {
    echo "=========================================="
    echo "Token Exchange + Vault JWT Auth Test"
    echo "=========================================="
    
    check_env_vars
    
    test_token_exchange_endpoint
    
    test_vault_connectivity
    
    check_vault_jwt_auth
    
    test_token_exchange
    
    test_mcp_server
    
    print_header "Test Summary"
    print_success "All tests completed!"
    print_info ""
    print_info "Next steps:"
    print_info "1. Obtain an ID token from your OIDC provider"
    print_info "2. Set ID_TOKEN environment variable"
    print_info "3. Re-run this script to test the complete flow"
    print_info "4. Or test with MCP client:"
    print_info "   curl -H 'Authorization: Bearer <ID_TOKEN>' http://$TRANSPORT_HOST:$TRANSPORT_PORT$MCP_ENDPOINT"
}

# Run main
main
