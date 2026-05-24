#!/bin/bash
# Example environment configuration for Token Exchange + Vault JWT Auth
# Copy this file and customize for your environment

# ============================================================================
# OIDC Provider Configuration (Choose Auth0 OR Okta)
# ============================================================================

# Enable OAuth authentication
export MCP_AUTH_ENABLED=true

# Option 1: Auth0 Configuration
export MCP_AUTH_PROVIDER=auth0
export AUTH0_DOMAIN=your-tenant.us.auth0.com
export AUTH0_AUDIENCE=your-api-identifier
export AUTH0_REQUIRED_SCOPES=mcp:tools,mcp:resources

# Option 2: Okta Configuration (comment out Auth0 if using Okta)
# export MCP_AUTH_PROVIDER=okta
# export OKTA_DOMAIN=dev-12345.okta.com
# export OKTA_AUDIENCE=api://vault-mcp-server
# export OKTA_AUTH_SERVER_ID=default
# export OKTA_REQUIRED_SCOPES=mcp:tools,mcp:resources

# ============================================================================
# Token Exchange Configuration (RFC 8693)
# ============================================================================

# Enable token exchange
export TOKEN_EXCHANGE_ENABLED=true

# Token broker endpoint
export TOKEN_EXCHANGE_BROKER_URL=https://token-broker.example.com/oauth/token

# Token exchange client credentials
export TOKEN_EXCHANGE_CLIENT_ID=mcp-server-client
export TOKEN_EXCHANGE_CLIENT_SECRET=your-secret-here

# Token exchange parameters
export TOKEN_EXCHANGE_AUDIENCE=vault
export TOKEN_EXCHANGE_RESOURCE=https://vault.example.com
export TOKEN_EXCHANGE_SCOPES=vault:read,vault:write

# Token introspection endpoint (optional)
export TOKEN_EXCHANGE_INTROSPECTION_URL=https://your-idp.com/oauth/introspect

# ============================================================================
# Vault Configuration
# ============================================================================

# Vault server address
export VAULT_ADDR=http://127.0.0.1:8200

# Vault JWT authentication settings
export VAULT_JWT_ROLE=mcp-role
export VAULT_JWT_AUTH_PATH=oidc

# Vault namespace (Enterprise only)
# export VAULT_NAMESPACE=your-namespace

# Skip TLS verification (NOT recommended for production)
export VAULT_SKIP_VERIFY=false

# ============================================================================
# MCP Server Configuration
# ============================================================================

# Transport mode
export TRANSPORT_MODE=streamable-http

# Server bind address and port
export TRANSPORT_HOST=127.0.0.1
export TRANSPORT_PORT=8080

# MCP endpoint path
export MCP_ENDPOINT=/mcp

# TLS configuration (required for non-localhost)
# export MCP_TLS_CERT_FILE=/path/to/cert.pem
# export MCP_TLS_KEY_FILE=/path/to/key.pem

# ============================================================================
# CORS Configuration
# ============================================================================

# CORS mode: strict, development, or disabled
export CORS_MODE=strict

# Allowed origins (comma-separated)
export CORS_ALLOWED_ORIGINS=https://app.example.com

# ============================================================================
# Logging Configuration
# ============================================================================

# Log level: debug, info, warn, error
export LOG_LEVEL=info

# Log file (optional, defaults to stderr)
# export LOG_FILE=/var/log/vault-mcp-server.log

# ============================================================================
# Rate Limiting Configuration
# ============================================================================

# Enable rate limiting
export RATE_LIMIT_ENABLED=true

# Requests per second
export RATE_LIMIT_RPS=10

# Burst size
export RATE_LIMIT_BURST=20

echo "Environment configured for Token Exchange + Vault JWT Auth"
echo "Start the server with: ./vault-mcp-server streamable-http"
