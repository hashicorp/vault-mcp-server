#!/bin/bash
# Example environment configuration for Vault JWT Authentication with MCP Server

# ============================================
# Vault Configuration
# ============================================

# Vault server address
export VAULT_ADDR='http://127.0.0.1:8200'

# ============================================
# JWT Authentication (Recommended)
# ============================================

# JWT token obtained from your OIDC provider (Okta, Auth0, etc.)
# This token is used to authenticate to Vault via the OIDC/JWT auth method
export VAULT_JWT_TOKEN='eyJraWQiOiJpa0xMd2pYSGd4b0tzeXRpazE1MjdiTzBtVkJ2T1p3REZLRTJvU1ZKU1FVIiwiYWxnIjoiUlMyNTYifQ...'

# Vault JWT role name (must be created in Vault with role_type="jwt")
# Default: mcp-role
export VAULT_JWT_ROLE='mcp-role'

# Vault auth path for OIDC/JWT authentication
# Default: oidc
export VAULT_JWT_AUTH_PATH='oidc'

# ============================================
# Alternative: Token Authentication
# ============================================

# Direct Vault token (only used if VAULT_JWT_TOKEN is not set)
# export VAULT_TOKEN='hvs.CAESIJ...'

# ============================================
# Optional Configuration
# ============================================

# Vault namespace (Enterprise only)
# export VAULT_NAMESPACE='my-namespace'

# Skip TLS verification (NOT recommended for production)
# export VAULT_SKIP_VERIFY='false'

# ============================================
# MCP Server Configuration
# ============================================

# Enable MCP OAuth authentication (for protecting MCP endpoints)
# export MCP_AUTH_ENABLED='true'
# export MCP_AUTH_PROVIDER='okta'
# export MCP_AUTH_DOMAIN='your-domain.okta.com'
# export MCP_AUTH_AUDIENCE='api://default'

# Server host and port
# export MCP_TRANSPORT_HOST='127.0.0.1'
# export MCP_TRANSPORT_PORT='8080'

# ============================================
# Usage Examples
# ============================================

# Example 1: Using JWT authentication (recommended)
# source example.jwt.env.sh
# ./bin/vault-mcp-server streamable-http

# Example 2: Using direct token authentication
# export VAULT_TOKEN='your-vault-token'
# ./bin/vault-mcp-server streamable-http

# ============================================
# How to Obtain JWT Token
# ============================================

# Option 1: Use the automated script
# ./scripts/get-jwt-and-run-mcp.sh

# Option 2: Manual PKCE flow (see docs/# Step 1: Generate PKCE codes and save t)

# Option 3: Using curl directly after PKCE flow
# See docs/VAULT_JWT_AUTH.md for complete instructions

echo "Vault JWT environment loaded"
echo "VAULT_ADDR: $VAULT_ADDR"
echo "JWT Token: ${VAULT_JWT_TOKEN:0:20}... (${#VAULT_JWT_TOKEN} chars)"
echo "JWT Role: $VAULT_JWT_ROLE"
